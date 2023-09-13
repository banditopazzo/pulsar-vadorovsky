use std::collections::HashMap;

use std::sync::OnceLock;

pub fn syscalls() -> &'static HashMap<usize, &'static str> {
    static SYSCALLS: OnceLock<HashMap<usize, &'static str>> = OnceLock::new();

    SYSCALLS.get_or_init(|| {
        let mut m = HashMap::new();

        m.insert(0, "IO_SETUP");
        m.insert(1, "IO_DESTROY");
        m.insert(2, "IO_SUBMIT");
        m.insert(3, "IO_CANCEL");
        m.insert(4, "IO_GETEVENTS");
        m.insert(5, "SETXATTR");
        m.insert(6, "LSETXATTR");
        m.insert(7, "FSETXATTR");
        m.insert(8, "GETXATTR");
        m.insert(9, "LGETXATTR");
        m.insert(10, "FGETXATTR");
        m.insert(11, "LISTXATTR");
        m.insert(12, "LLISTXATTR");
        m.insert(13, "FLISTXATTR");
        m.insert(14, "REMOVEXATTR");
        m.insert(15, "LREMOVEXATTR");
        m.insert(16, "FREMOVEXATTR");
        m.insert(17, "GETCWD");
        m.insert(18, "LOOKUP_DCOOKIE");
        m.insert(19, "EVENTFD2");
        m.insert(20, "EPOLL_CREATE1");
        m.insert(21, "EPOLL_CTL");
        m.insert(22, "EPOLL_PWAIT");
        m.insert(23, "DUP");
        m.insert(24, "DUP3");
        m.insert(25, "FCNTL");
        m.insert(26, "INOTIFY_INIT1");
        m.insert(27, "INOTIFY_ADD_WATCH");
        m.insert(28, "INOTIFY_RM_WATCH");
        m.insert(29, "IOCTL");
        m.insert(30, "IOPRIO_SET");
        m.insert(31, "IOPRIO_GET");
        m.insert(32, "FLOCK");
        m.insert(33, "MKNODAT");
        m.insert(34, "MKDIRAT");
        m.insert(35, "UNLINKAT");
        m.insert(36, "SYMLINKAT");
        m.insert(37, "LINKAT");
        m.insert(38, "RENAMEAT");
        m.insert(39, "UMOUNT2");
        m.insert(40, "MOUNT");
        m.insert(41, "PIVOT_ROOT");
        m.insert(42, "NFSSERVCTL");
        m.insert(43, "STATFS");
        m.insert(44, "FSTATFS");
        m.insert(45, "TRUNCATE");
        m.insert(46, "FTRUNCATE");
        m.insert(47, "FALLOCATE");
        m.insert(48, "FACCESSAT");
        m.insert(49, "CHDIR");
        m.insert(50, "FCHDIR");
        m.insert(51, "CHROOT");
        m.insert(52, "FCHMOD");
        m.insert(53, "FCHMODAT");
        m.insert(54, "FCHOWNAT");
        m.insert(55, "FCHOWN");
        m.insert(56, "OPENAT");
        m.insert(57, "CLOSE");
        m.insert(58, "VHANGUP");
        m.insert(59, "PIPE2");
        m.insert(60, "QUOTACTL");
        m.insert(61, "GETDENTS64");
        m.insert(62, "LSEEK");
        m.insert(63, "READ");
        m.insert(64, "WRITE");
        m.insert(65, "READV");
        m.insert(66, "WRITEV");
        m.insert(67, "PREAD64");
        m.insert(68, "PWRITE64");
        m.insert(69, "PREADV");
        m.insert(70, "PWRITEV");
        m.insert(71, "SENDFILE");
        m.insert(72, "PSELECT6");
        m.insert(73, "PPOLL");
        m.insert(74, "SIGNALFD4");
        m.insert(75, "VMSPLICE");
        m.insert(76, "SPLICE");
        m.insert(77, "TEE");
        m.insert(78, "READLINKAT");
        m.insert(79, "NEWFSTATAT");
        m.insert(80, "FSTAT");
        m.insert(81, "SYNC");
        m.insert(82, "FSYNC");
        m.insert(83, "FDATASYNC");
        m.insert(84, "SYNC_FILE_RANGE");
        m.insert(85, "TIMERFD_CREATE");
        m.insert(86, "TIMERFD_SETTIME");
        m.insert(87, "TIMERFD_GETTIME");
        m.insert(88, "UTIMENSAT");
        m.insert(89, "ACCT");
        m.insert(90, "CAPGET");
        m.insert(91, "CAPSET");
        m.insert(92, "PERSONALITY");
        m.insert(93, "EXIT");
        m.insert(94, "EXIT_GROUP");
        m.insert(95, "WAITID");
        m.insert(96, "SET_TID_ADDRESS");
        m.insert(97, "UNSHARE");
        m.insert(98, "FUTEX");
        m.insert(99, "SET_ROBUST_LIST");
        m.insert(100, "GET_ROBUST_LIST");
        m.insert(101, "NANOSLEEP");
        m.insert(102, "GETITIMER");
        m.insert(103, "SETITIMER");
        m.insert(104, "KEXEC_LOAD");
        m.insert(105, "INIT_MODULE");
        m.insert(106, "DELETE_MODULE");
        m.insert(107, "TIMER_CREATE");
        m.insert(108, "TIMER_GETTIME");
        m.insert(109, "TIMER_GETOVERRUN");
        m.insert(110, "TIMER_SETTIME");
        m.insert(111, "TIMER_DELETE");
        m.insert(112, "CLOCK_SETTIME");
        m.insert(113, "CLOCK_GETTIME");
        m.insert(114, "CLOCK_GETRES");
        m.insert(115, "CLOCK_NANOSLEEP");
        m.insert(116, "SYSLOG");
        m.insert(117, "PTRACE");
        m.insert(118, "SCHED_SETPARAM");
        m.insert(119, "SCHED_SETSCHEDULER");
        m.insert(120, "SCHED_GETSCHEDULER");
        m.insert(121, "SCHED_GETPARAM");
        m.insert(122, "SCHED_SETAFFINITY");
        m.insert(123, "SCHED_GETAFFINITY");
        m.insert(124, "SCHED_YIELD");
        m.insert(125, "SCHED_GET_PRIORITY_MAX");
        m.insert(126, "SCHED_GET_PRIORITY_MIN");
        m.insert(127, "SCHED_RR_GET_INTERVAL");
        m.insert(128, "RESTART_SYSCALL");
        m.insert(129, "KILL");
        m.insert(130, "TKILL");
        m.insert(131, "TGKILL");
        m.insert(132, "SIGALTSTACK");
        m.insert(133, "RT_SIGSUSPEND");
        m.insert(134, "RT_SIGACTION");
        m.insert(135, "RT_SIGPROCMASK");
        m.insert(136, "RT_SIGPENDING");
        m.insert(137, "RT_SIGTIMEDWAIT");
        m.insert(138, "RT_SIGQUEUEINFO");
        m.insert(139, "RT_SIGRETURN");
        m.insert(140, "SETPRIORITY");
        m.insert(141, "GETPRIORITY");
        m.insert(142, "REBOOT");
        m.insert(143, "SETREGID");
        m.insert(144, "SETGID");
        m.insert(145, "SETREUID");
        m.insert(146, "SETUID");
        m.insert(147, "SETRESUID");
        m.insert(148, "GETRESUID");
        m.insert(149, "SETRESGID");
        m.insert(150, "GETRESGID");
        m.insert(151, "SETFSUID");
        m.insert(152, "SETFSGID");
        m.insert(153, "TIMES");
        m.insert(154, "SETPGID");
        m.insert(155, "GETPGID");
        m.insert(156, "GETSID");
        m.insert(157, "SETSID");
        m.insert(158, "GETGROUPS");
        m.insert(159, "SETGROUPS");
        m.insert(160, "UNAME");
        m.insert(161, "SETHOSTNAME");
        m.insert(162, "SETDOMAINNAME");
        m.insert(163, "GETRLIMIT");
        m.insert(164, "SETRLIMIT");
        m.insert(165, "GETRUSAGE");
        m.insert(166, "UMASK");
        m.insert(167, "PRCTL");
        m.insert(168, "GETCPU");
        m.insert(169, "GETTIMEOFDAY");
        m.insert(170, "SETTIMEOFDAY");
        m.insert(171, "ADJTIMEX");
        m.insert(172, "GETPID");
        m.insert(173, "GETPPID");
        m.insert(174, "GETUID");
        m.insert(175, "GETEUID");
        m.insert(176, "GETGID");
        m.insert(177, "GETEGID");
        m.insert(178, "GETTID");
        m.insert(179, "SYSINFO");
        m.insert(180, "MQ_OPEN");
        m.insert(181, "MQ_UNLINK");
        m.insert(182, "MQ_TIMEDSEND");
        m.insert(183, "MQ_TIMEDRECEIVE");
        m.insert(184, "MQ_NOTIFY");
        m.insert(185, "MQ_GETSETATTR");
        m.insert(186, "MSGGET");
        m.insert(187, "MSGCTL");
        m.insert(188, "MSGRCV");
        m.insert(189, "MSGSND");
        m.insert(190, "SEMGET");
        m.insert(191, "SEMCTL");
        m.insert(192, "SEMTIMEDOP");
        m.insert(193, "SEMOP");
        m.insert(194, "SHMGET");
        m.insert(195, "SHMCTL");
        m.insert(196, "SHMAT");
        m.insert(197, "SHMDT");
        m.insert(198, "SOCKET");
        m.insert(199, "SOCKETPAIR");
        m.insert(200, "BIND");
        m.insert(201, "LISTEN");
        m.insert(202, "ACCEPT");
        m.insert(203, "CONNECT");
        m.insert(204, "GETSOCKNAME");
        m.insert(205, "GETPEERNAME");
        m.insert(206, "SENDTO");
        m.insert(207, "RECVFROM");
        m.insert(208, "SETSOCKOPT");
        m.insert(209, "GETSOCKOPT");
        m.insert(210, "SHUTDOWN");
        m.insert(211, "SENDMSG");
        m.insert(212, "RECVMSG");
        m.insert(213, "READAHEAD");
        m.insert(214, "BRK");
        m.insert(215, "MUNMAP");
        m.insert(216, "MREMAP");
        m.insert(217, "ADD_KEY");
        m.insert(218, "REQUEST_KEY");
        m.insert(219, "KEYCTL");
        m.insert(220, "CLONE");
        m.insert(221, "EXECVE");
        m.insert(222, "MMAP");
        m.insert(223, "FADVISE64");
        m.insert(224, "SWAPON");
        m.insert(225, "SWAPOFF");
        m.insert(226, "MPROTECT");
        m.insert(227, "MSYNC");
        m.insert(228, "MLOCK");
        m.insert(229, "MUNLOCK");
        m.insert(230, "MLOCKALL");
        m.insert(231, "MUNLOCKALL");
        m.insert(232, "MINCORE");
        m.insert(233, "MADVISE");
        m.insert(234, "REMAP_FILE_PAGES");
        m.insert(235, "MBIND");
        m.insert(236, "GET_MEMPOLICY");
        m.insert(237, "SET_MEMPOLICY");
        m.insert(238, "MIGRATE_PAGES");
        m.insert(239, "MOVE_PAGES");
        m.insert(240, "RT_TGSIGQUEUEINFO");
        m.insert(241, "PERF_EVENT_OPEN");
        m.insert(242, "ACCEPT4");
        m.insert(243, "RECVMMSG");
        m.insert(260, "WAIT4");
        m.insert(261, "PRLIMIT64");
        m.insert(262, "FANOTIFY_INIT");
        m.insert(263, "FANOTIFY_MARK");
        m.insert(264, "NAME_TO_HANDLE_AT");
        m.insert(265, "OPEN_BY_HANDLE_AT");
        m.insert(266, "CLOCK_ADJTIME");
        m.insert(267, "SYNCFS");
        m.insert(268, "SETNS");
        m.insert(269, "SENDMMSG");
        m.insert(270, "PROCESS_VM_READV");
        m.insert(271, "PROCESS_VM_WRITEV");
        m.insert(272, "KCMP");
        m.insert(273, "FINIT_MODULE");
        m.insert(274, "SCHED_SETATTR");
        m.insert(275, "SCHED_GETATTR");
        m.insert(276, "RENAMEAT2");
        m.insert(277, "SECCOMP");
        m.insert(278, "GETRANDOM");
        m.insert(279, "MEMFD_CREATE");
        m.insert(280, "BPF");
        m.insert(281, "EXECVEAT");
        m.insert(282, "USERFAULTFD");
        m.insert(283, "MEMBARRIER");
        m.insert(284, "MLOCK2");
        m.insert(285, "COPY_FILE_RANGE");
        m.insert(286, "PREADV2");
        m.insert(287, "PWRITEV2");
        m.insert(288, "PKEY_MPROTECT");
        m.insert(289, "PKEY_ALLOC");
        m.insert(290, "PKEY_FREE");
        m.insert(291, "STATX");

        m
    })
}
