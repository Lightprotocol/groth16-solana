//! This module is a partial copy from
//! [solana-program](https://github.com/solana-labs/solana/blob/master/sdk/program/src/syscalls/definitions.rs),
//! which is licensed under Apache License 2.0.
//!
//! The purpose of the module is to provide definition of altbn128 compression syscall
//! without upgrading solana-program and Anchor just yet.

#[cfg(target_feature = "static-syscalls")]
macro_rules! define_syscall {
    (fn $name:ident($($arg:ident: $typ:ty),*) -> $ret:ty) => {
		#[inline]
        pub unsafe fn $name($($arg: $typ),*) -> $ret {
			// this enum is used to force the hash to be computed in a const context
			#[repr(usize)]
			enum Syscall {
				Code = sys_hash(stringify!($name)),
			}

            let syscall: extern "C" fn($($arg: $typ),*) -> $ret = core::mem::transmute(Syscall::Code);
            syscall($($arg),*)
        }

    };
    (fn $name:ident($($arg:ident: $typ:ty),*)) => {
        define_syscall!(fn $name($($arg: $typ),*) -> ());
    }
}

#[cfg(not(target_feature = "static-syscalls"))]
macro_rules! define_syscall {
	(fn $name:ident($($arg:ident: $typ:ty),*) -> $ret:ty) => {
		extern "C" {
			pub fn $name($($arg: $typ),*) -> $ret;
		}
	};
	(fn $name:ident($($arg:ident: $typ:ty),*)) => {
		define_syscall!(fn $name($($arg: $typ),*) -> ());
	}
}

define_syscall!(fn sol_alt_bn128_compression(op: u64, input: *const u8, input_size: u64, result: *mut u8) -> u64);
