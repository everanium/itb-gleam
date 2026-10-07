//// The maintenance operations that mutate a live Pipeline handle
//// between iterations: master rotation (--rekey-every) and blob
//// reopen (--blob-cycle-every).

import gleam/int
import gleam/option.{type Option, None, Some}
import itb3/pipeline.{type Pipeline}
import itb3_gleam.{type ItbError, ItbError}
import loop_payload
import loop_state.{Updates}
import loop_types.{type Run}

// Byte length of each fresh master drawn for a rotation. Matches the
// size Init auto-generates for both the parallax and the wrapper
// master.
const rekey_master_size = 32

/// Handle mutation. Runs the periodic Pipeline-mutating operations
/// after a completed iteration: master rotation (--rekey-every) and
/// blob reopen (--blob-cycle-every). Both intervals count per-worker
/// iterations; the warmup iteration (iter 0) never triggers because
/// the worker loop calls this for iter >= 1 only. Rekey rewrites the
/// outer-layer keying of a live handle and a blob reopen replaces the
/// handle outright; each takes the write lock, so in-flight cipher
/// calls on other workers drain before anything changes and no
/// encrypt is separated from its decrypt by either.
pub fn maintenance(run: Run, id: Int, iter: Int) -> Result(Nil, String) {
  case due(run.cfg.rekey_every, iter) {
    True ->
      case rekey_pipes(run, id, iter) {
        Ok(Nil) -> blob_stage(run, id, iter)
        Error(text) -> Error(text)
      }
    False -> blob_stage(run, id, iter)
  }
}

fn blob_stage(run: Run, id: Int, iter: Int) -> Result(Nil, String) {
  case due(run.cfg.blob_cycle_every, iter) {
    True -> blob_cycle_pipes(run, id, iter)
    False -> Ok(Nil)
  }
}

fn due(every: Int, iter: Int) -> Bool {
  case every {
    0 -> False
    _ -> iter % every == 0
  }
}

/// Master rotation. Rotates the parallax + wrapper masters on every
/// active Pipeline under the write lock and retains the refreshed
/// blob for subsequent blob reopens. Masters are drawn fresh from the
/// OS CSPRNG on every rotation regardless of --seed (master rotation
/// is pipeline keying, not plaintext content); a disabled layer
/// passes no bytes, which Rekey ignores. The eight inner seeds and
/// the MAC key are untouched by design — Rekey targets only the two
/// outer-layer master secrets.
fn rekey_pipes(run: Run, id: Int, iter: Int) -> Result(Nil, String) {
  let perm = master(run.cfg.parallax)
  let wrap = master(run.cfg.wrapper)
  let grant = loop_state.write_lock(run.state)
  case rekey_one(grant.stream_pipe, perm, wrap) {
    Error(e) -> {
      loop_state.write_unlock(run.state, loop_state.no_updates())
      Error(op_error(id, iter, "Rekey", run.stream_profile, e))
    }
    Ok(stream_blob) ->
      case rekey_one(grant.msg_pipe, perm, wrap) {
        Error(e) -> {
          loop_state.write_unlock(
            run.state,
            Updates(None, None, stream_blob, None),
          )
          Error(op_error(id, iter, "Rekey", run.msg_profile, e))
        }
        Ok(msg_blob) -> {
          loop_state.write_unlock(
            run.state,
            Updates(None, None, stream_blob, msg_blob),
          )
          let n = loop_state.bump_rekeys(run.counts)
          loop_types.log(
            "rekey: g"
            <> int.to_string(id)
            <> " iter "
            <> int.to_string(iter)
            <> " rotated parallax + wrapper masters (rekey #"
            <> int.to_string(n)
            <> ")",
          )
          Ok(Nil)
        }
      }
  }
}

fn master(enabled: Bool) -> BitArray {
  case enabled {
    True -> loop_payload.random_bytes(rekey_master_size)
    False -> <<>>
  }
}

fn rekey_one(
  pipe: Option(Pipeline),
  perm: BitArray,
  wrap: BitArray,
) -> Result(Option(BitArray), ItbError) {
  case pipe {
    None -> Ok(None)
    Some(p) ->
      case pipeline.rekey(p, perm, wrap) {
        Ok(blob) -> Ok(Some(blob))
        Error(e) -> Error(e)
      }
  }
}

/// Blob reopen. Reopens every active Pipeline from its retained blob
/// under the write lock: a fresh handle is loaded from the blob, the
/// running handle is freed, and the fresh one is swapped in, so every
/// later iteration round-trips through seeds and masters that
/// survived a blob crossing. The input is the blob Init or the latest
/// Rekey handed out, not a fresh Save: that is what a receiver holds,
/// and reopening from it proves the handed-out bytes rather than the
/// live state. The blob carries the Pipeline's full shape, so no
/// override reaches the reopen. On a Load failure the running handle
/// stays and the failure aborts the run.
fn blob_cycle_pipes(run: Run, id: Int, iter: Int) -> Result(Nil, String) {
  let grant = loop_state.write_lock(run.state)
  case reopen(grant.stream_pipe, grant.stream_blob) {
    Error(e) -> {
      loop_state.write_unlock(run.state, loop_state.no_updates())
      Error(op_error(id, iter, "Load", run.stream_profile, e))
    }
    Ok(stream_fresh) ->
      case reopen(grant.msg_pipe, grant.msg_blob) {
        Error(e) -> {
          let swapped = swap(grant.stream_pipe, stream_fresh)
          loop_state.write_unlock(
            run.state,
            Updates(swapped, None, None, None),
          )
          Error(op_error(id, iter, "Load", run.msg_profile, e))
        }
        Ok(msg_fresh) -> {
          let s = swap(grant.stream_pipe, stream_fresh)
          let m = swap(grant.msg_pipe, msg_fresh)
          loop_state.write_unlock(run.state, Updates(s, m, None, None))
          let n = loop_state.bump_blob_cycles(run.counts)
          loop_types.log(
            "blob-cycle: g"
            <> int.to_string(id)
            <> " iter "
            <> int.to_string(iter)
            <> " reopened from session blob (cycle #"
            <> int.to_string(n)
            <> ")",
          )
          Ok(Nil)
        }
      }
  }
}

fn reopen(
  pipe: Option(Pipeline),
  blob: BitArray,
) -> Result(Option(Pipeline), ItbError) {
  case pipe {
    None -> Ok(None)
    Some(_) ->
      case pipeline.load(blob) {
        Ok(fresh) -> Ok(Some(fresh))
        Error(e) -> Error(e)
      }
  }
}

// The running handle is released only once its replacement is in
// hand, so a failed Load leaves the Pipeline the run is using intact.
fn swap(old: Option(Pipeline), fresh: Option(Pipeline)) -> Option(Pipeline) {
  case old, fresh {
    Some(o), Some(f) -> {
      pipeline.free(o)
      Some(f)
    }
    _, _ -> None
  }
}

fn op_error(
  id: Int,
  iter: Int,
  op: String,
  profile: String,
  e: ItbError,
) -> String {
  let ItbError(status, detail) = e
  "g"
  <> int.to_string(id)
  <> " iter "
  <> int.to_string(iter)
  <> ": "
  <> op
  <> "("
  <> profile
  <> "): "
  <> loop_types.status_text(status, detail)
}
