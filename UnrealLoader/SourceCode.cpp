#define _WIN32_WINNT 0x0501 
#define WINVER 0x0501 
#define NTDDI_VERSION 0x05010000
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <string>
#include <MinHook.h>
#include <time.h>
#include <stdint.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <stdint.h>
#include <vector>
#include "fnv.h"


#pragma comment(lib,"libMinHook.x86.lib")

// Game.dll address
int GameDll = 0;

char *rand_string( char *str, size_t size )
{
	const char charset[ ] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	if ( size )
	{
		--size;
		for ( size_t n = 0; n < size; n++ )
		{
			int key = rand( ) % ( int )( sizeof charset - 1 );
			str[ n ] = charset[ key ];
		}
		str[ size ] = '\0';
	}
	return str;
}

char *rand_string_int( char *str, size_t size )
{
	const char charset[ ] = "123456789";
	if ( size )
	{
		--size;
		for ( size_t n = 0; n < size; n++ )
		{
			int key = rand( ) % ( int )( sizeof charset - 1 );
			str[ n ] = charset[ key ];
		}
		str[ size ] = '\0';
	}
	return str;
}


char* rand_string_alloc( size_t sizen )
{
	size_t size = sizen + 1;
	char *s = new char[ size + 1 ];
	if ( s )
	{
		rand_string( s, size );
	}
	return s;
}

char* rand_string_int_alloc( size_t sizen )
{
	size_t size = sizen + 1;


	char *s = new char[ size + 1 ];
	if ( s )
	{
		rand_string_int( s, size );
	}
	return s;
}



void FindLargestArray( const char* Signature, const char* Mask, int Out[ 2 ] )
{
	uint32_t t1 = 0;
	uint32_t t2 = strlen( Signature );
	uint32_t len = strlen( Mask );

	for ( auto j = t2; j < len; j++ )
	{
		if ( Mask[ j ] != 'x' )
			continue;

		auto count = strlen( &Signature[ j ] );

		if ( count > t2 )
		{
			t1 = j;
			t2 = count;
		}

		j += ( count - 1 );
	}

	Out[ 0 ] = t1;
	Out[ 1 ] = t2;
}

uint8_t* FindPattern( const uint8_t* Data, const uint32_t Length, const char* Signature, const char* Mask )
{

	int d[ 2 ] = { 0 };
	FindLargestArray( Signature, Mask, d );

	const auto len = static_cast< uint8_t >( strlen( Mask ) );
	const auto mbeg = static_cast< uint8_t >( d[ 0 ] );
	const auto mlen = static_cast< uint8_t >( d[ 1 ] );
	const auto mfirst = static_cast< uint8_t >( Signature[ mbeg ] );

	uint8_t wildcard[ UCHAR_MAX + 1 ] = { 0 };

	for ( auto i = mbeg; i < mbeg + mlen; i++ )
		wildcard[ ( uint8_t )Signature[ i ] ] = 1;

	for ( auto i = Length - len; i >= 0 && i != ( unsigned int )( -1 ); i-- )
	{
		auto c = Data[ i ];
		auto w = wildcard[ c ];
		auto k = 0;

		while ( w == 0 && i > mlen )
		{
			i -= mlen;
			w = wildcard[ Data[ i ] ];
			k = 1;
		}

		if ( k == 1 )
		{
			i++;
			continue;
		}

		if ( c != mfirst )
			continue;

		if ( i - mbeg < 0 || i - mbeg + len > Length || i == ( unsigned int )( -1 ) )
			return nullptr;

		for ( auto j = 0; j < len - 1; j++ )
		{
			if ( j == mbeg || Mask[ j ] != 'x' )
				continue;

			if ( Data[ i - mbeg + j ] != ( uint8_t )Signature[ j ] )
				break;

			if ( j + 1 == len - 1 )
				return ( uint8_t* )( Data + i - mbeg );
		}
	}

	return nullptr;
}


__int64 FileSize( const TCHAR *fileName )
{
	WIN32_FILE_ATTRIBUTE_DATA fad;
	if ( !GetFileAttributesEx( fileName, GetFileExInfoStandard, &fad ) )
		return -1; // error condition, could call GetLastError to find out more
	LARGE_INTEGER size;
	size.HighPart = fad.nFileSizeHigh;
	size.LowPart = fad.nFileSizeLow;
	return size.QuadPart;
}

BOOL CheckIfEventExists( LPCSTR lpName )
{
	HANDLE result; // eax@1
	BOOL handleexists; // edi@2

	result = CreateEventA( 0, 1, 0, lpName );
	if ( result )
	{
		handleexists = ( GetLastError( ) == 183 );
		CloseHandle( result );
		result = ( HANDLE )handleexists;
	}
	return result > 0;
}

void ReplaceOldStringToNewString( int startaddress, int size, const char * oldstring, const char * oldstringpattern, const char * newstring )
{
	void * CurrentAddr = ( void * )startaddress;
	void * NewAddr = ( void * )startaddress;
	uint32_t CurrentSize = size - 1000;

	while ( ( NewAddr = FindPattern( ( uint8_t * )CurrentAddr, CurrentSize, oldstring, oldstringpattern ) ) != nullptr )
	{
		CurrentSize = CurrentSize - ( ( int )NewAddr - ( int )CurrentAddr );
		DWORD oldprot;
		VirtualProtect( NewAddr, strlen( newstring ) + 1, PAGE_EXECUTE_READWRITE, &oldprot );
		WriteProcessMemory( GetCurrentProcess( ), NewAddr, newstring, strlen( newstring ), 0 );
		VirtualProtect( NewAddr, strlen( newstring ) + 1, oldprot, &oldprot );
	}
}

typedef unsigned short( FAR __stdcall * htons_p )( unsigned short hostshort );

htons_p htons_org;
htons_p htons_ptr;

char buffer[ 1024 ];

unsigned short newport;

unsigned short FAR __stdcall htons_my( unsigned short hostshort )
{
	if ( hostshort == ( unsigned short )6112 )
	{
		MH_DisableHook( htons_org );
		return htons_ptr( newport );
	}
	else
		return htons_ptr( hostshort );
}

char * WarcraftNewDefaultGamePortRegistry = 0;



int result = 0;
BOOL resultok = FALSE;


LPVOID TlsValue;
DWORD TlsIndex;
DWORD _W3XTlsIndex;

DWORD GetIndex( )
{
	return *( DWORD* )( _W3XTlsIndex );
}

DWORD GetW3TlsForIndex( DWORD index )
{
	DWORD pid = GetCurrentProcessId( );
	THREADENTRY32 te32;
	HANDLE hSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, pid );
	te32.dwSize = sizeof( THREADENTRY32 );

	if ( Thread32First( hSnap, &te32 ) )
	{
		do
		{
			if ( te32.th32OwnerProcessID == pid )
			{
				HANDLE hThread = OpenThread( THREAD_ALL_ACCESS, false, te32.th32ThreadID );
				if ( hThread )
				{
					CONTEXT ctx = { CONTEXT_SEGMENTS };
					LDT_ENTRY ldt;
					GetThreadContext( hThread, &ctx );
					GetThreadSelectorEntry( hThread, ctx.SegFs, &ldt );
					DWORD dwThreadBase = ldt.BaseLow | ( ldt.HighWord.Bytes.BaseMid <<
						16u ) | ( ldt.HighWord.Bytes.BaseHi << 24u );
					CloseHandle( hThread );
					if ( dwThreadBase == NULL )
						continue;
					DWORD* dwTLS = *( DWORD** )( dwThreadBase + 0xE10 + 4 * index );
					if ( dwTLS == NULL )
						continue;
					return ( DWORD )dwTLS;
				}
			}
		} while ( Thread32Next( hSnap, &te32 ) );
	}

	return NULL;
}

void SetTlsForMe( )
{
	TlsIndex = GetIndex( );
	LPVOID tls = ( LPVOID )GetW3TlsForIndex( TlsIndex );
	TlsValue = tls;
}

typedef int( __stdcall *sub_6F630200 )( int value );
sub_6F630200 sub_6F630200_org;
sub_6F630200 sub_6F630200_ptr;


DWORD WINAPI sub_6F630200_thread( LPVOID val )
{
	SetTlsForMe( );
	result = sub_6F630200_ptr( *( int* )val );
	resultok = TRUE;
	return 0;
}

int __stdcall sub_6F630200_my( int value )
{
	SetTlsForMe( );
	CreateThread( 0, 0, sub_6F630200_thread, &value, 0, 0 );
	while ( true )
	{
		Sleep( 1000 );
	}
	return 0;
}

typedef unsigned int( __stdcall * pOrdinal509 )( char *str, char a3, int a2 );

pOrdinal509 Ordinal509_org;
pOrdinal509 Ordinal509_ptr;

#define MASK_56 (((u_int64_t)1<<56)-1) /* i.e., (u_int64_t)0xffffffffffffff */

u_int64_t GetBufHash( const char * data, size_t data_len )
{
	u_int64_t hash;
	hash = fnv_64_buf( ( void * )data, ( size_t )data_len, FNV1_64_INIT );
	hash = ( hash >> 56 ) ^ ( hash & MASK_56 );
	return hash;
}

std::vector<u_int64_t> StrList;

void LogMsg( const char * msg )
{
	FILE * f;
	fopen_s( &f, ".\\log.txt", "a+" );
	fprintf_s( f, "%s\r\n", msg );
	fclose( f );
}


void ClearLogMsg( )
{
	FILE * f;
	fopen_s( &f, ".\\log.txt", "w" );
	fclose( f );
}

unsigned int __stdcall Ordinal509my( char *str, char a3, int a2 )
{
	if ( str && *str )
	{
		size_t len = strlen( str );
		if ( len > 0 )
		{
			u_int64_t hash = GetBufHash( str, len );
			for ( u_int64_t i : StrList )
			{
				if ( i == hash )
					return Ordinal509_ptr( str, a3, a2 );
			}

			StrList.push_back( hash );
			LogMsg( str );
		}
	}

	return Ordinal509_ptr( str, a3, a2 );
}
struct StringRep {
	void**				vtable;		//0x0
	uint32_t			refCount;	//0x4
	uint32_t			hash;		//0x8
	uint32_t			list_C;		//0xC
	uint32_t			unk_10;		//0x10
	void *				nexttxtdata;//0x14
	StringRep*			next;		//0x18
	char*				text;		//0x1C
};//sizeof = 0x20

struct RCString {
	void**				vtable;		//0x0
	uint32_t			unk_4;		//0x4
	StringRep*			stringRep;	//0x8
};//sizeof = 0xC 



typedef int( __thiscall * pConvertStrToJassStr )( RCString * jStr, const char * cStr );

pConvertStrToJassStr str2jstr;

pConvertStrToJassStr str2jstr_ptr;

int __fastcall pConvertStrToJassStr_my( RCString * jStr, int unused, const char * cStr )
{
	int retval = str2jstr_ptr( jStr, cStr );
	char addrs[ 200 ];
	sprintf_s( addrs, "%X", jStr );
	MessageBox( 0, addrs, " ", 0 );
	return retval;
}


BOOL WINAPI DllMain( HINSTANCE hDLL, UINT reason, LPVOID reserved )
{

	if ( reason == DLL_PROCESS_ATTACH )
	{
		BOOL force = strstr( GetCommandLine( ), "-force" ) > 0;


		srand( ( unsigned int )time( 0 ) );

		MH_Initialize( );

		int maxrand = 100;

		HMODULE GameDllModule = GetModuleHandle( "Game.dll" );

		if ( !GameDllModule )
		{
			MessageBox( 0, "No game dll", " ERROR ", 0 );
			return FALSE;
		}

		char GameDllPath[ MAX_PATH ];
		GetModuleFileName( GameDllModule, GameDllPath, sizeof( GameDllPath ) );

		__int64 GameDllSize = FileSize( GameDllPath );

		GameDll = ( int )GameDllModule;
		_W3XTlsIndex = 0xAB7BF4 + GameDll;

		/*	sub_6F630200_org = ( sub_6F630200 )( GameDll + 0x630200 );
			MH_CreateHook( sub_6F630200_org, &sub_6F630200_my, reinterpret_cast< void** >( &sub_6F630200_ptr ) );
			MH_EnableHook( sub_6F630200_org );
			*/

			/*ClearLogMsg( );

			Ordinal509_org = ( pOrdinal509 )( (int)GetModuleHandle("Storm.dll") + 0x34440 );
			MH_CreateHook( Ordinal509_org, &Ordinal509my, reinterpret_cast< void** >( &Ordinal509_ptr ) );
			MH_EnableHook( Ordinal509_org );*/


		char * WarcraftEventName = "Warcraft III Game Application";

		BOOL WarcraftAllreadyRunning = CheckIfEventExists( WarcraftEventName );

		char * WarcraftEventNamePattern = "xxxxxxxx?xxx?xxxx?xxxxxxxxxxx";


		char * WarcraftGameDefaultPort = "6112";
		char * WarcraftGameDefaultPortPattern = "xxxx";

		char * WarcraftGameDefaultPortInRegistry = "netgameport";
		char * WarcraftGameDefaultPortInRegistryPattern = "xxxxxxxxxxx";

		char * WarcraftBattleNetCache = "bncache.dat";
		char * WarcraftBattleNetCachePattern = "xxxxxxxxxxx";

		char  * WarcraftLastReplay = "LastReplay";
		char  * WarcraftLastReplayPattern = "xxxxxxxxxx";

		char  * WarcraftTempReplay = "TempReplay";
		char  * WarcraftTempReplayPattern = "xxxxxxxxxx";


		char * WarcraftEventRenamer = rand_string_alloc( strlen( WarcraftEventName ) );

		char * WarcraftNewDefaultGamePort = rand_string_int_alloc( 4 );

		newport = atoi( WarcraftNewDefaultGamePort ) + 1;

		WarcraftNewDefaultGamePortRegistry = rand_string_alloc( strlen( WarcraftGameDefaultPortInRegistry ) );

		char * WarcraftNewBattleNetCache = rand_string_int_alloc( strlen( WarcraftBattleNetCache ) );

		char * WarcraftNewLastReplay = rand_string_int_alloc( strlen( WarcraftLastReplay ) );
		char * WarcraftNewTempReplay = rand_string_int_alloc( strlen( WarcraftTempReplay ) );
		str2jstr = ( pConvertStrToJassStr )( GameDll + 0x11300 );
		MH_CreateHook( str2jstr, &pConvertStrToJassStr_my, reinterpret_cast< void** >( &str2jstr_ptr ) );
		MH_EnableHook( str2jstr );


		if ( !WarcraftAllreadyRunning && !force )
		{
			return TRUE;
		}
		else
		{
			while ( CheckIfEventExists( WarcraftEventRenamer ) && maxrand-- > 0 )
			{
				WarcraftEventRenamer = rand_string_alloc( strlen( WarcraftEventName ) );

				WarcraftNewDefaultGamePort = rand_string_int_alloc( 4 );

				newport = atoi( WarcraftNewDefaultGamePort ) + 1;

				WarcraftNewDefaultGamePortRegistry = rand_string_alloc( strlen( WarcraftGameDefaultPortInRegistry ) );

				WarcraftNewBattleNetCache = rand_string_int_alloc( strlen( WarcraftBattleNetCache ) );

				WarcraftNewLastReplay = rand_string_int_alloc( strlen( WarcraftLastReplay ) );

				WarcraftNewTempReplay = rand_string_int_alloc( strlen( WarcraftTempReplay ) );
			}

			ReplaceOldStringToNewString( GameDll, ( int )GameDllSize, WarcraftEventName, WarcraftEventNamePattern, WarcraftEventRenamer );

			ReplaceOldStringToNewString( GameDll, ( int )GameDllSize, WarcraftGameDefaultPort, WarcraftGameDefaultPortPattern, WarcraftNewDefaultGamePort );

			ReplaceOldStringToNewString( GameDll, ( int )GameDllSize, WarcraftGameDefaultPortInRegistry, WarcraftGameDefaultPortInRegistryPattern, WarcraftNewDefaultGamePortRegistry );

			ReplaceOldStringToNewString( GameDll, ( int )GameDllSize, WarcraftBattleNetCache, WarcraftBattleNetCachePattern, WarcraftNewBattleNetCache );

			ReplaceOldStringToNewString( GameDll, ( int )GameDllSize, WarcraftLastReplay, WarcraftLastReplayPattern, WarcraftNewLastReplay );

			ReplaceOldStringToNewString( GameDll, ( int )GameDllSize, WarcraftTempReplay, WarcraftTempReplayPattern, WarcraftNewTempReplay );


			HMODULE ws32 = GetModuleHandle( "Ws2_32.dll" );
			if ( !ws32 )
			{
				MessageBox( 0, "Not full loaded, works only multiwindows.", "ERROR NO Ws2_32.dll FOUND", 0 );
				return FALSE;
			}

			htons_org = ( htons_p )GetProcAddress( ws32, "htons" );
			MH_CreateHook( htons_org, &htons_my, reinterpret_cast< void** >( &htons_ptr ) );
			MH_EnableHook( htons_org );





		}
	
	}
	else if ( reason == DLL_PROCESS_DETACH )
	{
		if ( htons_org )
			MH_DisableHook( htons_org );

		if ( WarcraftNewDefaultGamePortRegistry )
		{
			HKEY hKey;
			RegOpenKeyExA( HKEY_CURRENT_USER,
				"Software\\Blizzard Entertainment\\WarCraft III\\Gameplay",
				0L,
				KEY_ALL_ACCESS,
				&hKey );

			RegDeleteValue( hKey, WarcraftNewDefaultGamePortRegistry );
			RegCloseKey( hKey );
		}

		MH_Uninitialize( );
	}
	return TRUE;
}
