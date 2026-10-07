//// The state every worker shares: the Pipeline handles, the retained
//// blobs, the reader / writer lock that keeps iterations clear of
//// handle mutation, the stop request, and the rekey and blob-cycle
//// totals.
////
//// Gleam-specific. BEAM has no reader / writer lock primitive, so
//// the lock is a process that owns the handles and hands them out: a
//// reader is granted immediately unless a writer holds or is
//// waiting, a writer waits until the last reader has left. The
//// handles travel with the grant rather than being cached by the
//// worker, because a blob reopen frees the running handle and swaps
//// a fresh one in — a worker holding the value from launch would be
//// calling into a released resource from the first cycle onwards.
//// Every lock holder is watched, so a worker that dies holding
//// either side releases it instead of wedging the run. The admission
//// rules below are the policy; the receive and the ref-based reply
//// under them are primitives of `loop_ffi`.

import gleam/list
import gleam/option.{type Option, None, Some}
import itb3/pipeline.{type Pipeline}
import loop_ffi.{type Counts, type Flags, type Pid, type Ref}

// Slot 1 of the atomics word carries the stop request; slots 1 and 2
// of the counters array carry the rekey and blob-cycle totals.
const slot_stop = 1

const count_rekeys = 1

const count_blob_cycles = 2

/// The fields one maintenance operation replaces; the rest are kept.
pub type Updates {
  Updates(
    stream_pipe: Option(Pipeline),
    msg_pipe: Option(Pipeline),
    stream_blob: Option(BitArray),
    msg_blob: Option(BitArray),
  )
}

pub fn no_updates() -> Updates {
  Updates(None, None, None, None)
}

/// The handles a read grant carries.
pub type ReadGrant {
  ReadGrant(stream_pipe: Option(Pipeline), msg_pipe: Option(Pipeline))
}

/// The handles and retained blobs a write grant carries.
pub type WriteGrant {
  WriteGrant(
    stream_pipe: Option(Pipeline),
    msg_pipe: Option(Pipeline),
    stream_blob: BitArray,
    msg_blob: BitArray,
  )
}

pub type LockMsg {
  ReadLock(pid: Pid, ref: Ref)
  WriteLock(pid: Pid, ref: Ref)
  ReadUnlock(pid: Pid)
  WriteUnlock(pid: Pid, updates: Updates)
  AskHandles(pid: Pid, ref: Ref)
  LockDown(pid: Pid, reason: String)
  Shutdown(pid: Pid, ref: Ref)
}

type S {
  S(
    stream_pipe: Option(Pipeline),
    msg_pipe: Option(Pipeline),
    stream_blob: BitArray,
    msg_blob: BitArray,
    readers: List(Pid),
    writer: Option(Pid),
    wait_readers: List(#(Pid, Ref)),
    wait_writers: List(#(Pid, Ref)),
  )
}

// ------------------------------------------------------------------
// Stop request and counters — lock-free, so a worker's per-iteration
// check never queues behind the lock process.
// ------------------------------------------------------------------

pub fn new_flags() -> Flags {
  loop_ffi.atomics_new(1)
}

pub fn request_stop(flags: Flags) -> Nil {
  loop_ffi.atomics_put(flags, slot_stop, 1)
}

pub fn stop_requested(flags: Flags) -> Bool {
  loop_ffi.atomics_get(flags, slot_stop) == 1
}

pub fn new_counts() -> Counts {
  loop_ffi.counters_new(2)
}

pub fn bump_rekeys(counts: Counts) -> Int {
  loop_ffi.counters_add(counts, count_rekeys, 1)
  loop_ffi.counters_get(counts, count_rekeys)
}

pub fn bump_blob_cycles(counts: Counts) -> Int {
  loop_ffi.counters_add(counts, count_blob_cycles, 1)
  loop_ffi.counters_get(counts, count_blob_cycles)
}

pub fn rekeys(counts: Counts) -> Int {
  loop_ffi.counters_get(counts, count_rekeys)
}

pub fn blob_cycles(counts: Counts) -> Int {
  loop_ffi.counters_get(counts, count_blob_cycles)
}

// ------------------------------------------------------------------
// The lock process
// ------------------------------------------------------------------

pub fn start(
  stream_pipe: Option(Pipeline),
  msg_pipe: Option(Pipeline),
  stream_blob: BitArray,
  msg_blob: BitArray,
) -> Pid {
  loop_ffi.spawn_fn(fn() {
    run(S(
      stream_pipe,
      msg_pipe,
      stream_blob,
      msg_blob,
      [],
      None,
      [],
      [],
    ))
  })
}

pub fn stop_process(pid: Pid) -> Nil {
  let _: Nil = loop_ffi.call(pid, Shutdown)
  Nil
}

/// Grants the read side and hands back the handles in force at that
/// instant. Cipher calls run in the caller, not here: routing them
/// through this process would serialise every worker and remove the
/// shared-handle property the harness exists to exercise.
pub fn read_lock(pid: Pid) -> ReadGrant {
  loop_ffi.call(pid, ReadLock)
}

pub fn read_unlock(pid: Pid) -> Nil {
  loop_ffi.send(pid, ReadUnlock(loop_ffi.self_pid()))
}

pub fn write_lock(pid: Pid) -> WriteGrant {
  loop_ffi.call(pid, WriteLock)
}

/// Releases the write side, installing whatever the maintenance
/// produced.
pub fn write_unlock(pid: Pid, updates: Updates) -> Nil {
  loop_ffi.send(pid, WriteUnlock(loop_ffi.self_pid(), updates))
}

/// The handles without taking the lock, for the shutdown path after
/// every worker has returned.
pub fn handles(pid: Pid) -> ReadGrant {
  loop_ffi.call(pid, AskHandles)
}

/// Routes a worker's abnormal exit into the lock so its claim is
/// dropped; a normal exit sends nothing.
pub fn watch(worker: Pid, lock: Pid) -> Nil {
  loop_ffi.watch_process(worker, lock, LockDown)
}

// ------------------------------------------------------------------

fn run(st: S) -> Nil {
  case loop_ffi.receive_any() {
    ReadLock(pid, ref) -> run(request_read(st, pid, ref))
    WriteLock(pid, ref) -> run(request_write(st, pid, ref))
    ReadUnlock(pid) -> run(grant(release_reader(st, pid)))
    WriteUnlock(pid, updates) ->
      run(grant(release_writer(apply_updates(st, updates), pid)))
    AskHandles(pid, ref) -> {
      loop_ffi.reply(pid, ref, read_grant(st))
      run(st)
    }
    // A holder that died never sends its unlock; drop its claim so
    // the run can finish instead of wedging.
    LockDown(pid, _reason) ->
      run(grant(release_writer(release_reader(st, pid), pid)))
    Shutdown(pid, ref) -> loop_ffi.reply(pid, ref, Nil)
  }
}

fn read_grant(st: S) -> ReadGrant {
  ReadGrant(st.stream_pipe, st.msg_pipe)
}

fn write_grant(st: S) -> WriteGrant {
  WriteGrant(st.stream_pipe, st.msg_pipe, st.stream_blob, st.msg_blob)
}

fn request_read(st: S, pid: Pid, ref: Ref) -> S {
  case st.writer, st.wait_writers {
    None, [] -> {
      loop_ffi.reply(pid, ref, read_grant(st))
      S(..st, readers: [pid, ..st.readers])
    }
    _, _ ->
      S(..st, wait_readers: list.append(st.wait_readers, [#(pid, ref)]))
  }
}

fn request_write(st: S, pid: Pid, ref: Ref) -> S {
  case st.writer, st.readers {
    None, [] -> {
      loop_ffi.reply(pid, ref, write_grant(st))
      S(..st, writer: Some(pid))
    }
    _, _ ->
      S(..st, wait_writers: list.append(st.wait_writers, [#(pid, ref)]))
  }
}

// Writer preference: a queued writer goes first, so a steady stream
// of iterations cannot starve a rekey that is already waiting.
fn grant(st: S) -> S {
  case st.writer, st.readers, st.wait_writers, st.wait_readers {
    None, [], [#(pid, ref), ..rest], _ -> {
      let next = S(..st, wait_writers: rest)
      loop_ffi.reply(pid, ref, write_grant(next))
      S(..next, writer: Some(pid))
    }
    None, _, [], [_, ..] -> {
      let waiting = st.wait_readers
      let next =
        S(
          ..st,
          readers: list.append(
            list.map(waiting, fn(e) { e.0 }),
            st.readers,
          ),
          wait_readers: [],
        )
      list.each(waiting, fn(e) { loop_ffi.reply(e.0, e.1, read_grant(next)) })
      next
    }
    _, _, _, _ -> st
  }
}

fn release_reader(st: S, pid: Pid) -> S {
  S(..st, readers: list.filter(st.readers, fn(p) { p != pid }))
}

fn release_writer(st: S, pid: Pid) -> S {
  case st.writer {
    Some(held) if held == pid -> S(..st, writer: None)
    _ -> st
  }
}

fn apply_updates(st: S, updates: Updates) -> S {
  let st1 = case updates.stream_pipe {
    Some(p) -> S(..st, stream_pipe: Some(p))
    None -> st
  }
  let st2 = case updates.msg_pipe {
    Some(p) -> S(..st1, msg_pipe: Some(p))
    None -> st1
  }
  let st3 = case updates.stream_blob {
    Some(b) -> S(..st2, stream_blob: b)
    None -> st2
  }
  case updates.msg_blob {
    Some(b) -> S(..st3, msg_blob: b)
    None -> st3
  }
}
