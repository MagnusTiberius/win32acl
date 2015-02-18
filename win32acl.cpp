// win32acl.cpp : Defines the entry point for the console application.
//



#include "stdafx.h"
#include <fstream>
#include <iostream>
#include <aclapi.h>
#include <windows.h>

using namespace std;


int _tmain(int argc, _TCHAR* argv[])
{
	if ( argc != 2 ) {
		cout<<"usage: win32acl " <<" <filename>\n";
		return 1;
	}

	LPCWSTR fname = argv[1];

	//fname = L"C:\\windows";

	wcout << "file:" << fname << "\n";

	PSECURITY_DESCRIPTOR psd = NULL;
	PACL pdacl;
	ACL_SIZE_INFORMATION aclSize = {0};
	PSID sidowner = NULL;
	PSID sidgroup = NULL;


	ULONG result = GetNamedSecurityInfo(fname
			,SE_FILE_OBJECT
			,OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION 
			,&sidowner
			,&sidgroup
			,&pdacl
			,NULL
			,&psd);

	if (result != ERROR_SUCCESS){ return NULL;}

	wchar_t* oname = new TCHAR[512];
	DWORD namelen;
	wchar_t* doname = new TCHAR[512];
	DWORD domainnamelen;
	SID_NAME_USE peUse;
	ACCESS_ALLOWED_ACE* ace;

	LookupAccountSid(NULL, sidowner,  oname, &namelen, doname, &domainnamelen, &peUse);
	wcout<<"Owner: " << doname << "/" << oname <<"\n";

	LookupAccountSid(NULL, sidgroup,  oname, &namelen, doname, &domainnamelen, &peUse);
	wcout<<"Group: " << doname << "/" << oname <<"\n";

	wcout<< "\n\n\n::DACL::" << "\n";
	SID *sid;
	unsigned long i, mask;
	char *stringsid;

	for (int i=0; i<(*pdacl).AceCount; i++) {
		int c=1;
		BOOL b = GetAce(pdacl, i, (PVOID*)&ace);
		//SID *sid = (SID *) ace->SidStart;
		if (((ACCESS_ALLOWED_ACE *) ace)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE) {
			sid = (SID *) &((ACCESS_ALLOWED_ACE *) ace)->SidStart;
			LookupAccountSid(NULL, sid,  oname, &namelen, doname, &domainnamelen, &peUse);
			wcout<<"SID: " << doname << "/" << oname <<"\n";
			mask = ((ACCESS_ALLOWED_ACE *) ace)->Mask;
		}
		else if (((ACCESS_DENIED_ACE *) ace)->Header.AceType == ACCESS_DENIED_ACE_TYPE) {
			sid = (SID *) &((ACCESS_DENIED_ACE *) ace)->SidStart;
			LookupAccountSid(NULL, sid,  oname, &namelen, doname, &domainnamelen, &peUse);
			wcout<<"SID: " << doname << "/" << oname <<"\n";
			mask = ((ACCESS_DENIED_ACE *) ace)->Mask;
		}
		else printf("Other ACE\n");

		wcout<<"ACE: mask:" << ace->Mask << " sidStart:" << ace->SidStart << " header type=" << ace->Header.AceType << " header flags=" << ace->Header.AceFlags <<"\n";
		if (DELETE & ace->Mask) {
			wcout<< " DELETE" << "\n";
		}
		if (FILE_GENERIC_READ & ace->Mask) {
			wcout<< " FILE_GENERIC_READ" << "\n";
		}
		if (FILE_GENERIC_WRITE & ace->Mask) {
			wcout<< " FILE_GENERIC_WRITE" << "\n";
		}
		if (FILE_GENERIC_EXECUTE & ace->Mask) {
			wcout<< " FILE_GENERIC_EXECUTE" << "\n";
		}
		if (GENERIC_READ & ace->Mask) {
			wcout<< " GENERIC_READ" << "\n";
		}
		if (GENERIC_WRITE & ace->Mask) {
			wcout<< " GENERIC_WRITE" << "\n";
		}
		if (GENERIC_EXECUTE & ace->Mask) {
			wcout<< " GENERIC_EXECUTE" << "\n";
		}
		if (GENERIC_ALL & ace->Mask) {
			wcout<< " GENERIC_ALL" << "\n";
		}
		if (READ_CONTROL & ace->Mask) {
			wcout<< " READ_CONTROL" << "\n";
		}
		if (WRITE_DAC & ace->Mask) {
			wcout<< " WRITE_DAC" << "\n";
		}
		if (WRITE_OWNER & ace->Mask) {
			wcout<< " WRITE_OWNER" << "\n";
		}
		if (SYNCHRONIZE & ace->Mask) {
			wcout<< " SYNCHRONIZE" << "\n";
		}
		wcout<<"\n";
	}

	SECURITY_DESCRIPTOR* p1 = (SECURITY_DESCRIPTOR*)psd;

	wcout<< "\n\n\n::SECURITY_DESCRIPTOR_CONTROL::" << "\n";

	SECURITY_DESCRIPTOR_CONTROL ctrl = (*p1).Control;
		if (SE_OWNER_DEFAULTED & ctrl) {
			wcout<< " SE_OWNER_DEFAULTED" << "\n";
		}
		if (SE_DACL_PRESENT & ctrl) {
			wcout<< " SE_DACL_PRESENT" << "\n";
		}
		if (SE_DACL_DEFAULTED & ctrl) {
			wcout<< " SE_DACL_DEFAULTED" << "\n";
		}
		if (SE_SACL_PRESENT & ctrl) {
			wcout<< " SE_SACL_PRESENT" << "\n";
		}
		if (SE_SACL_DEFAULTED & ctrl) {
			wcout<< " SE_SACL_DEFAULTED" << "\n";
		}
		if (SE_DACL_AUTO_INHERIT_REQ & ctrl) {
			wcout<< " SE_DACL_AUTO_INHERIT_REQ" << "\n";
		}
		if (SE_SACL_AUTO_INHERIT_REQ & ctrl) {
			wcout<< " SE_SACL_AUTO_INHERIT_REQ" << "\n";
		}
		if (SE_SACL_AUTO_INHERITED & ctrl) {
			wcout<< " SE_SACL_AUTO_INHERITED" << "\n";
		}
		if (SE_DACL_PROTECTED & ctrl) {
			wcout<< " SE_DACL_PROTECTED" << "\n";
		}
		if (SE_SACL_PROTECTED & ctrl) {
			wcout<< " SE_SACL_PROTECTED" << "\n";
		}
		if (SE_RM_CONTROL_VALID & ctrl) {
			wcout<< " SE_RM_CONTROL_VALID" << "\n";
		}
		if (SE_SELF_RELATIVE & ctrl) {
			wcout<< " SE_SELF_RELATIVE" << "\n";
		}

	LocalFree(psd);
	LocalFree(sidowner);
	LocalFree(pdacl);
	return 0;
}

