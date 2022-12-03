
extrn SysCallIndex : DWORD
extrn draw : proc;
extrn jmpOrgPresentDWM2:proc
extrn draw2 : proc;
extrn jmpOrgPresentDWM3:proc
extrn orgGetBufferAsm:proc
extrn DXGIGetBufferEx:proc
.data
.code




public shellSysCall64
shellSysCall64 PROC  

mov eax,SysCallIndex;
mov r10,rcx;
syscall;
ret;

shellSysCall64 ENDP

public ImGuiDraw
ImGuiDraw PROC  
 

push rax  
push rbx
push rcx
push rdx
push rbp
push rsp
push rsi
push rdi
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15
pushfq 

sub rsp, 8h  ;为什么要减去8 因此进入call之前 rsp必须与0x10倍数，不如必定异常
call draw;
add rsp, 8h

popfq
pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rdi
pop rsi
pop rsp
pop rbp
pop rdx
pop rcx
pop rbx
pop rax
jmp  qword ptr[jmpOrgPresentDWM2];

ImGuiDraw ENDP




public ImGuiDraw2
ImGuiDraw2 PROC  
 

int 3
push rax  
push rbx
push rcx
push rdx
push rbp
push rsp
push rsi
push rdi
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15
pushfq 

sub rsp, 8h  ;为什么要减去8 因此进入call之前 rsp必须与0x10倍数，不如必定异常
call draw2;
add rsp, 8h

popfq
pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rdi
pop rsi
pop rsp
pop rbp
pop rdx
pop rcx
pop rbx
pop rax
jmp  qword ptr[jmpOrgPresentDWM3];

ImGuiDraw2 ENDP



public DXGIGetBufferAsm
DXGIGetBufferAsm PROC  
 

int 3
push rax  
push rbx
push rcx
push rdx
push rbp
push rsp
push rsi
push rdi
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15
pushfq 

sub rsp, 8h  ;为什么要减去8 因此进入call之前 rsp必须与0x10倍数，不如必定异常
mov rcx,r15;
call DXGIGetBufferEx;
add rsp, 8h

popfq
pop r15
pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rdi
pop rsi
pop rsp
pop rbp
pop rdx
pop rcx
pop rbx
pop rax
jmp  qword ptr[orgGetBufferAsm];

DXGIGetBufferAsm ENDP




END