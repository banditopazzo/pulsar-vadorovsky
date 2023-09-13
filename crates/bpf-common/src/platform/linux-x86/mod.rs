use std::collections::HashMap;

use std::sync::OnceLock;

pub fn syscalls() -> &'static HashMap<usize, &'static str> {
    static SYSCALLS: OnceLock<HashMap<usize, &'static str>> = OnceLock::new();

    SYSCALLS.get_or_init(|| {
        let mut m = HashMap::new();

        m.insert(0, "RESTART_SYSCALL");
        m.insert(1, "EXIT");
        m.insert(2, "FORK");
        m.insert(3, "READ");
        m.insert(4, "WRITE");
        m.insert(5, "OPEN");
        m.insert(6, "CLOSE");
        m.insert(7, "WAITPID");
        m.insert(8, "CREAT");
        m.insert(9, "LINK");
        m.insert(10, "UNLINK");
        m.insert(11, "EXECVE");
        m.insert(12, "CHDIR");
        m.insert(13, "TIME");
        m.insert(14, "MKNOD");
        m.insert(15, "CHMOD");
        m.insert(16, "LCHOWN");
        m.insert(17, "BREAK");
        m.insert(18, "OLDSTAT");
        m.insert(19, "LSEEK");
        m.insert(20, "GETPID");
        m.insert(21, "MOUNT");
        m.insert(22, "UMOUNT");
        m.insert(23, "SETUID");
        m.insert(24, "GETUID");
        m.insert(25, "STIME");
        m.insert(26, "PTRACE");
        m.insert(27, "ALARM");
        m.insert(28, "OLDFSTAT");
        m.insert(29, "PAUSE");
        m.insert(30, "UTIME");
        m.insert(31, "STTY");
        m.insert(32, "GTTY");
        m.insert(33, "ACCESS");
        m.insert(34, "NICE");
        m.insert(35, "FTIME");
        m.insert(36, "SYNC");
        m.insert(37, "KILL");
        m.insert(38, "RENAME");
        m.insert(39, "MKDIR");
        m.insert(40, "RMDIR");
        m.insert(41, "DUP");
        m.insert(42, "PIPE");
        m.insert(43, "TIMES");
        m.insert(44, "PROF");
        m.insert(45, "BRK");
        m.insert(46, "SETGID");
        m.insert(47, "GETGID");
        m.insert(48, "SIGNAL");
        m.insert(49, "GETEUID");
        m.insert(50, "GETEGID");
        m.insert(51, "ACCT");
        m.insert(52, "UMOUNT2");
        m.insert(53, "LOCK");
        m.insert(54, "IOCTL");
        m.insert(55, "FCNTL");
        m.insert(56, "MPX");
        m.insert(57, "SETPGID");
        m.insert(58, "ULIMIT");
        m.insert(59, "OLDOLDUNAME");
        m.insert(60, "UMASK");
        m.insert(61, "CHROOT");
        m.insert(62, "USTAT");
        m.insert(63, "DUP2");
        m.insert(64, "GETPPID");
        m.insert(65, "GETPGRP");
        m.insert(66, "SETSID");
        m.insert(67, "SIGACTION");
        m.insert(68, "SGETMASK");
        m.insert(69, "SSETMASK");
        m.insert(70, "SETREUID");
        m.insert(71, "SETREGID");
        m.insert(72, "SIGSUSPEND");
        m.insert(73, "SIGPENDING");
        m.insert(74, "SETHOSTNAME");
        m.insert(75, "SETRLIMIT");
        m.insert(76, "GETRLIMIT");
        m.insert(77, "GETRUSAGE");
        m.insert(78, "GETTIMEOFDAY");
        m.insert(79, "SETTIMEOFDAY");
        m.insert(80, "GETGROUPS");
        m.insert(81, "SETGROUPS");
        m.insert(82, "SELECT");
        m.insert(83, "SYMLINK");
        m.insert(84, "OLDLSTAT");
        m.insert(85, "READLINK");
        m.insert(86, "USELIB");
        m.insert(87, "SWAPON");
        m.insert(88, "REBOOT");
        m.insert(89, "READDIR");
        m.insert(90, "MMAP");
        m.insert(91, "MUNMAP");
        m.insert(92, "TRUNCATE");
        m.insert(93, "FTRUNCATE");
        m.insert(94, "FCHMOD");
        m.insert(95, "FCHOWN");
        m.insert(96, "GETPRIORITY");
        m.insert(97, "SETPRIORITY");
        m.insert(98, "PROFIL");
        m.insert(99, "STATFS");
        m.insert(100, "FSTATFS");
        m.insert(101, "IOPERM");
        m.insert(102, "SOCKETCALL");
        m.insert(103, "SYSLOG");
        m.insert(104, "SETITIMER");
        m.insert(105, "GETITIMER");
        m.insert(106, "STAT");
        m.insert(107, "LSTAT");
        m.insert(108, "FSTAT");
        m.insert(109, "OLDUNAME");
        m.insert(110, "IOPL");
        m.insert(111, "VHANGUP");
        m.insert(112, "IDLE");
        m.insert(113, "VM86OLD");
        m.insert(114, "WAIT4");
        m.insert(115, "SWAPOFF");
        m.insert(116, "SYSINFO");
        m.insert(117, "IPC");
        m.insert(118, "FSYNC");
        m.insert(119, "SIGRETURN");
        m.insert(120, "CLONE");
        m.insert(121, "SETDOMAINNAME");
        m.insert(122, "UNAME");
        m.insert(123, "MODIFY_LDT");
        m.insert(124, "ADJTIMEX");
        m.insert(125, "MPROTECT");
        m.insert(126, "SIGPROCMASK");
        m.insert(127, "CREATE_MODULE");
        m.insert(128, "INIT_MODULE");
        m.insert(129, "DELETE_MODULE");
        m.insert(130, "GET_KERNEL_SYMS");
        m.insert(131, "QUOTACTL");
        m.insert(132, "GETPGID");
        m.insert(133, "FCHDIR");
        m.insert(134, "BDFLUSH");
        m.insert(135, "SYSFS");
        m.insert(136, "PERSONALITY");
        m.insert(137, "AFS_SYSCALL");
        m.insert(138, "SETFSUID");
        m.insert(139, "SETFSGID");
        m.insert(140, "_LLSEEK");
        m.insert(141, "GETDENTS");
        m.insert(142, "_NEWSELECT");
        m.insert(143, "FLOCK");
        m.insert(144, "MSYNC");
        m.insert(145, "READV");
        m.insert(146, "WRITEV");
        m.insert(147, "GETSID");
        m.insert(148, "FDATASYNC");
        m.insert(149, "_SYSCTL");
        m.insert(150, "MLOCK");
        m.insert(151, "MUNLOCK");
        m.insert(152, "MLOCKALL");
        m.insert(153, "MUNLOCKALL");
        m.insert(154, "SCHED_SETPARAM");
        m.insert(155, "SCHED_GETPARAM");
        m.insert(156, "SCHED_SETSCHEDULER");
        m.insert(157, "SCHED_GETSCHEDULER");
        m.insert(158, "SCHED_YIELD");
        m.insert(159, "SCHED_GET_PRIORITY_MAX");
        m.insert(160, "SCHED_GET_PRIORITY_MIN");
        m.insert(161, "SCHED_RR_GET_INTERVAL");
        m.insert(162, "NANOSLEEP");
        m.insert(163, "MREMAP");
        m.insert(164, "SETRESUID");
        m.insert(165, "GETRESUID");
        m.insert(166, "VM86");
        m.insert(167, "QUERY_MODULE");
        m.insert(168, "POLL");
        m.insert(169, "NFSSERVCTL");
        m.insert(170, "SETRESGID");
        m.insert(171, "GETRESGID");
        m.insert(172, "PRCTL");
        m.insert(173, "RT_SIGRETURN");
        m.insert(174, "RT_SIGACTION");
        m.insert(175, "RT_SIGPROCMASK");
        m.insert(176, "RT_SIGPENDING");
        m.insert(177, "RT_SIGTIMEDWAIT");
        m.insert(178, "RT_SIGQUEUEINFO");
        m.insert(179, "RT_SIGSUSPEND");
        m.insert(180, "PREAD64");
        m.insert(181, "PWRITE64");
        m.insert(182, "CHOWN");
        m.insert(183, "GETCWD");
        m.insert(184, "CAPGET");
        m.insert(185, "CAPSET");
        m.insert(186, "SIGALTSTACK");
        m.insert(187, "SENDFILE");
        m.insert(188, "GETPMSG");
        m.insert(189, "PUTPMSG");
        m.insert(190, "VFORK");
        m.insert(191, "UGETRLIMIT");
        m.insert(192, "MMAP2");
        m.insert(193, "TRUNCATE64");
        m.insert(194, "FTRUNCATE64");
        m.insert(195, "STAT64");
        m.insert(196, "LSTAT64");
        m.insert(197, "FSTAT64");
        m.insert(198, "LCHOWN32");
        m.insert(199, "GETUID32");
        m.insert(200, "GETGID32");
        m.insert(201, "GETEUID32");
        m.insert(202, "GETEGID32");
        m.insert(203, "SETREUID32");
        m.insert(204, "SETREGID32");
        m.insert(205, "GETGROUPS32");
        m.insert(206, "SETGROUPS32");
        m.insert(207, "FCHOWN32");
        m.insert(208, "SETRESUID32");
        m.insert(209, "GETRESUID32");
        m.insert(210, "SETRESGID32");
        m.insert(211, "GETRESGID32");
        m.insert(212, "CHOWN32");
        m.insert(213, "SETUID32");
        m.insert(214, "SETGID32");
        m.insert(215, "SETFSUID32");
        m.insert(216, "SETFSGID32");
        m.insert(217, "PIVOT_ROOT");
        m.insert(218, "MINCORE");
        m.insert(219, "MADVISE");
        m.insert(220, "GETDENTS64");
        m.insert(221, "FCNTL64");
        m.insert(224, "GETTID");
        m.insert(225, "READAHEAD");
        m.insert(226, "SETXATTR");
        m.insert(227, "LSETXATTR");
        m.insert(228, "FSETXATTR");
        m.insert(229, "GETXATTR");
        m.insert(230, "LGETXATTR");
        m.insert(231, "FGETXATTR");
        m.insert(232, "LISTXATTR");
        m.insert(233, "LLISTXATTR");
        m.insert(234, "FLISTXATTR");
        m.insert(235, "REMOVEXATTR");
        m.insert(236, "LREMOVEXATTR");
        m.insert(237, "FREMOVEXATTR");
        m.insert(238, "TKILL");
        m.insert(239, "SENDFILE64");
        m.insert(240, "FUTEX");
        m.insert(241, "SCHED_SETAFFINITY");
        m.insert(242, "SCHED_GETAFFINITY");
        m.insert(243, "SET_THREAD_AREA");
        m.insert(244, "GET_THREAD_AREA");
        m.insert(245, "IO_SETUP");
        m.insert(246, "IO_DESTROY");
        m.insert(247, "IO_GETEVENTS");
        m.insert(248, "IO_SUBMIT");
        m.insert(249, "IO_CANCEL");
        m.insert(250, "FADVISE64");
        m.insert(252, "EXIT_GROUP");
        m.insert(253, "LOOKUP_DCOOKIE");
        m.insert(254, "EPOLL_CREATE");
        m.insert(255, "EPOLL_CTL");
        m.insert(256, "EPOLL_WAIT");
        m.insert(257, "REMAP_FILE_PAGES");
        m.insert(258, "SET_TID_ADDRESS");
        m.insert(259, "TIMER_CREATE");
        m.insert(260, "TIMER_SETTIME");
        m.insert(261, "TIMER_GETTIME");
        m.insert(262, "TIMER_GETOVERRUN");
        m.insert(263, "TIMER_DELETE");
        m.insert(264, "CLOCK_SETTIME");
        m.insert(265, "CLOCK_GETTIME");
        m.insert(266, "CLOCK_GETRES");
        m.insert(267, "CLOCK_NANOSLEEP");
        m.insert(268, "STATFS64");
        m.insert(269, "FSTATFS64");
        m.insert(270, "TGKILL");
        m.insert(271, "UTIMES");
        m.insert(272, "FADVISE64_64");
        m.insert(273, "VSERVER");
        m.insert(274, "MBIND");
        m.insert(275, "GET_MEMPOLICY");
        m.insert(276, "SET_MEMPOLICY");
        m.insert(277, "MQ_OPEN");
        m.insert(278, "MQ_UNLINK");
        m.insert(279, "MQ_TIMEDSEND");
        m.insert(280, "MQ_TIMEDRECEIVE");
        m.insert(281, "MQ_NOTIFY");
        m.insert(282, "MQ_GETSETATTR");
        m.insert(283, "KEXEC_LOAD");
        m.insert(284, "WAITID");
        m.insert(286, "ADD_KEY");
        m.insert(287, "REQUEST_KEY");
        m.insert(288, "KEYCTL");
        m.insert(289, "IOPRIO_SET");
        m.insert(290, "IOPRIO_GET");
        m.insert(291, "INOTIFY_INIT");
        m.insert(292, "INOTIFY_ADD_WATCH");
        m.insert(293, "INOTIFY_RM_WATCH");
        m.insert(294, "MIGRATE_PAGES");
        m.insert(295, "OPENAT");
        m.insert(296, "MKDIRAT");
        m.insert(297, "MKNODAT");
        m.insert(298, "FCHOWNAT");
        m.insert(299, "FUTIMESAT");
        m.insert(300, "FSTATAT64");
        m.insert(301, "UNLINKAT");
        m.insert(302, "RENAMEAT");
        m.insert(303, "LINKAT");
        m.insert(304, "SYMLINKAT");
        m.insert(305, "READLINKAT");
        m.insert(306, "FCHMODAT");
        m.insert(307, "FACCESSAT");
        m.insert(308, "PSELECT6");
        m.insert(309, "PPOLL");
        m.insert(310, "UNSHARE");
        m.insert(311, "SET_ROBUST_LIST");
        m.insert(312, "GET_ROBUST_LIST");
        m.insert(313, "SPLICE");
        m.insert(314, "SYNC_FILE_RANGE");
        m.insert(315, "TEE");
        m.insert(316, "VMSPLICE");
        m.insert(317, "MOVE_PAGES");
        m.insert(318, "GETCPU");
        m.insert(319, "EPOLL_PWAIT");
        m.insert(320, "UTIMENSAT");
        m.insert(321, "SIGNALFD");
        m.insert(322, "TIMERFD_CREATE");
        m.insert(323, "EVENTFD");
        m.insert(324, "FALLOCATE");
        m.insert(325, "TIMERFD_SETTIME");
        m.insert(326, "TIMERFD_GETTIME");
        m.insert(327, "SIGNALFD4");
        m.insert(328, "EVENTFD2");
        m.insert(329, "EPOLL_CREATE1");
        m.insert(330, "DUP3");
        m.insert(331, "PIPE2");
        m.insert(332, "INOTIFY_INIT1");
        m.insert(333, "PREADV");
        m.insert(334, "PWRITEV");
        m.insert(335, "RT_TGSIGQUEUEINFO");
        m.insert(336, "PERF_EVENT_OPEN");
        m.insert(337, "RECVMMSG");
        m.insert(338, "FANOTIFY_INIT");
        m.insert(339, "FANOTIFY_MARK");
        m.insert(340, "PRLIMIT64");
        m.insert(341, "NAME_TO_HANDLE_AT");
        m.insert(342, "OPEN_BY_HANDLE_AT");
        m.insert(343, "CLOCK_ADJTIME");
        m.insert(344, "SYNCFS");
        m.insert(345, "SENDMMSG");
        m.insert(346, "SETNS");
        m.insert(347, "PROCESS_VM_READV");
        m.insert(348, "PROCESS_VM_WRITEV");
        m.insert(349, "KCMP");
        m.insert(350, "FINIT_MODULE");
        m.insert(351, "SCHED_SETATTR");
        m.insert(352, "SCHED_GETATTR");
        m.insert(353, "RENAMEAT2");
        m.insert(354, "SECCOMP");
        m.insert(355, "GETRANDOM");
        m.insert(356, "MEMFD_CREATE");
        m.insert(357, "BPF");
        m.insert(358, "EXECVEAT");
        m
    })
}
