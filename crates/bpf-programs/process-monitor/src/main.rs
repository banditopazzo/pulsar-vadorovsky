#![no_std]
#![no_main]

use aya_bpf::{
    cty::{c_char, c_int, c_long, c_ulong},
    macros::{kprobe, lsm},
    programs::{LsmContext, ProbeContext},
    BpfContext,
};

use process_monitor_events::{ForkEvent, ProcessEvent, ProcessEventPayload, ProcessEventVariant};

mod maps;
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use vmlinux::{list_head, mm_struct, signal_struct, task_struct};

#[no_mangle]
static log_level: i32 = 0;

#[no_mangle]
static LINUX_KERNEL_VERSION: i32 = 0;

#[allow(improper_ctypes)]
extern "C" {
    fn cgroup_kn(cgrp: *const vmlinux::cgroup) -> *const vmlinux::kernfs_node;

    fn file_f_path_mnt(file: *const vmlinux::file) -> *const vmlinux::vfsmount;
    fn file_f_path_dentry(file: *const vmlinux::file) -> *const vmlinux::dentry;

    fn kernfs_node_id(kn: *const vmlinux::kernfs_node) -> u64;

    fn linux_binprm_file(bprm: *const vmlinux::linux_binprm) -> *const vmlinux::file;
    fn linux_binprm_argc(bprm: *const vmlinux::linux_binprm) -> c_int;
    fn linux_binprm_filename(bprm: *const vmlinux::linux_binprm) -> *const c_char;

    fn signal_struct_live_counter(signal: *const vmlinux::signal_struct) -> c_int;

    fn mm_struct_arg_start(mm: *const vmlinux::mm_struct) -> c_ulong;
    fn mm_struct_arg_end(mm: *const vmlinux::mm_struct) -> c_ulong;

    fn task_struct_mm(task: *const task_struct) -> *const mm_struct;
    fn task_struct_exit_code(task: *const task_struct) -> c_int;
    fn task_struct_pid(task: *const task_struct) -> c_int;
    fn task_struct_tgid(task: *const task_struct) -> c_int;
    fn task_struct_parent(task: *const task_struct) -> *const task_struct;
    fn task_struct_children_next(task: *const task_struct) -> *const list_head;
    fn task_struct_sibling_next(task: *const task_struct) -> *const list_head;
    fn task_struct_group_leader(task: *const task_struct) -> *const task_struct;
    fn task_struct_signal(task: *const task_struct) -> *const signal_struct;
}

pub struct Task {
    inner: *const vmlinux::task_struct,
}

impl From<*const vmlinux::task_struct> for Task {
    fn from(inner: *const vmlinux::task_struct) -> Self {
        Self { inner }
    }
}

impl Task {
    pub fn exit_code(&self) -> Result<c_int, c_long> {
        let exit_code = unsafe { task_struct_exit_code(self.inner) };
        if exit_code < 0 {
            return Err(exit_code.into());
        }
        Ok(exit_code)
    }

    pub fn pid(&self) -> Result<c_int, c_long> {
        let pid = unsafe { task_struct_pid(self.inner) };
        if pid < 0 {
            return Err(pid.into());
        }
        Ok(pid)
    }

    pub fn tgid(&self) -> Result<c_int, c_long> {
        let tgid = unsafe { task_struct_tgid(self.inner) };
        if tgid < 0 {
            return Err(tgid.into());
        }
        Ok(tgid)
    }

    pub fn parent(&self) -> Result<Self, c_long> {
        let inner = unsafe { task_struct_parent(self.inner) };
        if inner.is_null() {
            return Err(-1);
        }
        Ok(Self { inner })
    }

    pub fn group_leader(&self) -> Result<Self, c_long> {
        let inner = unsafe { task_struct_group_leader(self.inner) };
        if inner.is_null() {
            return Err(-1);
        }
        Ok(Self { inner })
    }
}

#[repr(C)]
pub struct Event {
    pub pid: i32,
    pub tgid: i32,
}

#[kprobe]
pub fn security_task_alloc(ctx: ProbeContext) -> u32 {
    match try_security_task_alloc(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_security_task_alloc(ctx: ProbeContext) -> Result<(), c_long> {
    let task: *const vmlinux::task_struct = ctx.arg(0).ok_or(-1)?;
    let task: Task = task.into();
    handle_task_alloc(&ctx, task)?;
    Ok(())
}

// #[lsm(hook = "task_alloc")]
// pub fn task_alloc(ctx: LsmContext) -> i32 {
//     match try_task_alloc(ctx) {
//         Ok(_) => 0,
//         Err(_) => 0,
//     }
// }
//
// fn try_task_alloc(ctx: LsmContext) -> Result<(), c_long> {
//     let task: *const vmlinux::task_struct = unsafe { ctx.arg(0) };
//     // let task: Task = task.into();
//     // handle_task_alloc(&ctx, task)?;
//
//     let pid = unsafe { task_struct_pid(task) };
//     let tgid = unsafe { task_struct_tgid(task) };
//
//     EVENTS.output(&ctx, &Event { pid, tgid }, 0);
//
//     Ok(())
// }

fn handle_task_alloc<C>(ctx: &C, task: Task) -> Result<(), c_long>
// fn handle_task_alloc<C>(ctx: &C, task: *const vmlinux::task_struct) -> Result<(), c_long>
where
    C: BpfContext,
{
    let pid = task.pid()?;
    // let tgid = task.tgid()?;
    // let pid = unsafe { task_struct_pid(task) };
    // let tgid = unsafe { task_struct_tgid(task) };
    // EVENTS.output(ctx, &Event { pid, tgid }, 0);
    maps::map_output_process_event.output(
        ctx,
        &ProcessEvent {
            timestamp: 0,
            pid,
            payload: ProcessEventPayload {
                event_type: 0,
                payload: ProcessEventVariant {
                    fork: ForkEvent { ppid: pid },
                },
            },
        },
        0,
    );
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
