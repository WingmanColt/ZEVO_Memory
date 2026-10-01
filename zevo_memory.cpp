// ZEVO MEMORY v1.2 - Metamod / Metamod-r plugin (Linux, HLDS / ReHLDS, CS 1.6)
//
// Hunk / cache memory
//  - Prints the hunk memory block at map start and when precaching has finished.
//  - Prints it again when free hunk crosses 15% / 10% / 5% (once each per map).
//  - Prints "CACHE ALLOCATION FAILURE" when a precache request is larger than
//    the free hunk.
// Precache tracking (new in 1.2)
//  - Counts precached models / sounds / generic files per map (limit 512 each).
//  - Warns at 90% of the limit and when the limit is exceeded.
//  - Cvars (read-only counters, usable from AMXX with get_cvar_num):
//        zevo_pc_models  zevo_pc_sounds  zevo_pc_generic  zevo_pc_total
//    and zevo_pc_autolist (1 = write the full list when precaching finishes).
// Commands (server console / rcon)
//  - zevo_memory                       print the hunk block now
//  - zevo_memory verbose [0|1]         log every precached resource as it happens
//  - zevo_list [models|sounds|generic|all] [file]
//                                      list precached resources (or write to file)
//  - zevo_top [n]                      the n biggest precached files (default 20)
//
// Files (all under <gamedir>/addons/zevo_memory/, created automatically):
//    zevo_memory.log          event log
//    precache_<map>.txt       full precache list of the last map
//
// Build (32-bit):
//   g++ -m32 -O2 -shared -fPIC -std=gnu++11 -fno-exceptions -fno-rtti \
//       -fno-stack-protector -fno-asynchronous-unwind-tables -D_FORTIFY_SOURCE=0 \
//       -Dlinux -D__linux__ <include paths> zevo_memory.cpp \
//       -nodefaultlibs -Wl,--as-needed -lc -o zevo_memory_mm_i386.so

#include <extdll.h>
#include <meta_api.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <sys/stat.h>

meta_globals_t *gpMetaGlobals;
gamedll_funcs_t *gpGamedllFuncs;
mutil_funcs_t *gpMetaUtilFuncs;
enginefuncs_t g_engfuncs;
globalvars_t *gpGlobals;

plugin_info_t Plugin_info = {
	META_INTERFACE_VERSION, "ZevoMemory", "1.2", __DATE__, "Zevo", "",
	"ZEVOMEM", PT_ANYTIME, PT_ANYTIME
};

#define TAG "[ZEVO MEMORY] "
#define KB(x) ((long long)(x) / 1024)
#define MB(x) ((double)(x) / 1048576.0)

static char g_gameDir[128];
static char g_logPath[512];

// ------------------------------------------------------------------ logging
// Out: console + log file.   Con: console only.
static void Out(const char *fmt, ...)
{
	char buf[1024];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	g_engfuncs.pfnServerPrint(buf);

	if (g_logPath[0]) {
		FILE *f = fopen(g_logPath, "a");
		if (f) { fputs(buf, f); fclose(f); }
	}
}

static void Con(const char *fmt, ...)
{
	char buf[1024];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	g_engfuncs.pfnServerPrint(buf);
}

// ------------------------------------------------------- engine symbol probe
static unsigned int g_engBase;
static char g_enginePath[512];
static int *p_hunk_size, *p_hunk_low_used, *p_hunk_high_used;
static bool g_probeOk = false;
static char g_hunkNames[400];          // diagnostics: symbols containing "hunk"

static unsigned long ParseHex(const char *&p)
{
	unsigned long v = 0;
	for (;; p++) {
		char c = *p;
		if (c >= '0' && c <= '9') v = v * 16 + (c - '0');
		else if (c >= 'a' && c <= 'f') v = v * 16 + (c - 'a' + 10);
		else if (c >= 'A' && c <= 'F') v = v * 16 + (c - 'A' + 10);
		else break;
	}
	return v;
}

static bool FindEngineMapping()
{
	FILE *f = fopen("/proc/self/maps", "r");
	if (!f) return false;
	char line[1024];
	bool found = false;
	while (fgets(line, sizeof(line), f)) {
		char *slash = strchr(line, '/');
		if (!slash || !strstr(line, "/engine_") || !strstr(line, ".so")) continue;
		const char *p = line;
		unsigned long lo = ParseHex(p);
		if (*p != '-') continue;
		p++;
		ParseHex(p);                       // hi
		while (*p == ' ') p++;
		while (*p && *p != ' ') p++;       // perms
		while (*p == ' ') p++;
		unsigned long off = ParseHex(p);   // file offset
		if (off != 0) continue;            // only the first mapping of the file
		strncpy(g_enginePath, slash, sizeof(g_enginePath) - 1);
		g_enginePath[sizeof(g_enginePath) - 1] = 0;
		size_t n = strlen(g_enginePath);
		while (n && (g_enginePath[n - 1] == '\n' || g_enginePath[n - 1] == '\r' || g_enginePath[n - 1] == ' '))
			g_enginePath[--n] = 0;
		g_engBase = (unsigned int)lo;
		found = true;
		break;
	}
	fclose(f);
	return found;
}

static void ScanEngineSymbols(const char *const *want, unsigned int *out, int nwant)
{
	FILE *f = fopen(g_enginePath, "rb");
	if (!f) return;
	Elf32_Ehdr eh;
	if (fread(&eh, sizeof(eh), 1, f) != 1 || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
	    eh.e_ident[EI_CLASS] != ELFCLASS32 || eh.e_shoff == 0 || eh.e_shnum == 0 ||
	    eh.e_shentsize != sizeof(Elf32_Shdr)) { fclose(f); return; }

	Elf32_Shdr *sh = (Elf32_Shdr *)malloc(eh.e_shnum * sizeof(Elf32_Shdr));
	if (!sh) { fclose(f); return; }
	if (fseek(f, (long)eh.e_shoff, SEEK_SET) != 0 ||
	    fread(sh, sizeof(Elf32_Shdr), eh.e_shnum, f) != eh.e_shnum) { free(sh); fclose(f); return; }

	size_t hl = strlen(g_hunkNames);
	for (int i = 0; i < eh.e_shnum; i++) {
		if (sh[i].sh_type != SHT_SYMTAB && sh[i].sh_type != SHT_DYNSYM) continue;
		if (sh[i].sh_link >= eh.e_shnum) continue;
		const Elf32_Shdr &st = sh[sh[i].sh_link];
		if (sh[i].sh_size == 0 || sh[i].sh_size > (64u << 20) || st.sh_size == 0 || st.sh_size > (64u << 20)) continue;

		Elf32_Sym *syms = (Elf32_Sym *)malloc(sh[i].sh_size);
		char *str = (char *)malloc(st.sh_size + 1);
		bool ok = syms && str &&
			fseek(f, (long)sh[i].sh_offset, SEEK_SET) == 0 && fread(syms, 1, sh[i].sh_size, f) == sh[i].sh_size &&
			fseek(f, (long)st.sh_offset, SEEK_SET) == 0 && fread(str, 1, st.sh_size, f) == st.sh_size;
		if (ok) {
			str[st.sh_size] = 0;
			unsigned int n = sh[i].sh_size / sizeof(Elf32_Sym);
			for (unsigned int j = 0; j < n; j++) {
				if (syms[j].st_name >= st.sh_size || syms[j].st_value == 0) continue;
				const char *name = str + syms[j].st_name;
				for (int k = 0; k < nwant; k++)
					if (!out[k] && strcmp(name, want[k]) == 0) out[k] = syms[j].st_value;
				if (strcasestr(name, "hunk") && hl + strlen(name) + 2 < sizeof(g_hunkNames) &&
				    !strstr(g_hunkNames, name)) {
					strcat(g_hunkNames, name);
					strcat(g_hunkNames, " ");
					hl = strlen(g_hunkNames);
				}
			}
		}
		free(syms);
		free(str);
	}
	free(sh);
	fclose(f);
}

static void ProbeHunk()
{
	g_hunkNames[0] = 0;
	if (!FindEngineMapping()) return;
	static const char *const want[3] = { "hunk_size", "hunk_low_used", "hunk_high_used" };
	unsigned int addr[3] = { 0, 0, 0 };
	ScanEngineSymbols(want, addr, 3);
	if (!addr[0] || !addr[1] || !addr[2]) return;

	p_hunk_size      = (int *)(g_engBase + addr[0]);
	p_hunk_low_used  = (int *)(g_engBase + addr[1]);
	p_hunk_high_used = (int *)(g_engBase + addr[2]);

	int sz = *p_hunk_size, lo = *p_hunk_low_used, hi = *p_hunk_high_used;
	g_probeOk = sz > (1 << 20) && sz < (1 << 30) && lo >= 0 && hi >= 0 && (long long)lo + hi <= sz;
}

// ------------------------------------------------------- resource registry
enum { RT_MODEL = 0, RT_SOUND = 1, RT_GENERIC = 2, RT_COUNT = 3 };
#define MAX_RES       2048          // entries stored per type (count keeps going)
#define ENGINE_LIMIT  512           // GoldSrc limit per type
#define WARN_AT       (ENGINE_LIMIT * 9 / 10)

struct ResEntry { char name[96]; long long size; };
static ResEntry g_res[RT_COUNT][MAX_RES];
static int g_resCount[RT_COUNT];
static int g_limitState[RT_COUNT];                // 0 ok, 1 warned at 90%, 2 warned over limit
static const char *const g_typeName[RT_COUNT] = { "Models", "Sounds", "Generic" };

#define SEEN_SIZE 16384             // power of two
static unsigned int g_seen[SEEN_SIZE];

static unsigned int HashName(int type, const char *s)
{
	unsigned int h = 2166136261u ^ ((unsigned int)(type + 1) * 0x9E3779B1u);
	for (; *s; s++) h = (h ^ (unsigned char)((*s >= 'A' && *s <= 'Z') ? *s + 32 : *s)) * 16777619u;
	return h ? h : 1u;
}

static bool SeenInsert(int type, const char *name)   // true if newly inserted
{
	unsigned int h = HashName(type, name);
	unsigned int i = h & (SEEN_SIZE - 1);
	for (int n = 0; n < SEEN_SIZE; n++, i = (i + 1) & (SEEN_SIZE - 1)) {
		if (g_seen[i] == h) return false;
		if (g_seen[i] == 0) { g_seen[i] = h; return true; }
	}
	return false;
}

// cvars (read-only counters)
static cvar_t cv_models   = { (char *)"zevo_pc_models",   (char *)"0", FCVAR_EXTDLL, 0.0f, NULL };
static cvar_t cv_sounds   = { (char *)"zevo_pc_sounds",   (char *)"0", FCVAR_EXTDLL, 0.0f, NULL };
static cvar_t cv_generic  = { (char *)"zevo_pc_generic",  (char *)"0", FCVAR_EXTDLL, 0.0f, NULL };
static cvar_t cv_total    = { (char *)"zevo_pc_total",    (char *)"0", FCVAR_EXTDLL, 0.0f, NULL };
static cvar_t cv_autolist = { (char *)"zevo_pc_autolist", (char *)"1", FCVAR_EXTDLL, 1.0f, NULL };
static cvar_t *p_cv[4];                 // models, sounds, generic, total
static cvar_t *p_cvAuto;

static void RegisterCvars()
{
	g_engfuncs.pfnCVarRegister(&cv_models);
	g_engfuncs.pfnCVarRegister(&cv_sounds);
	g_engfuncs.pfnCVarRegister(&cv_generic);
	g_engfuncs.pfnCVarRegister(&cv_total);
	g_engfuncs.pfnCVarRegister(&cv_autolist);
	p_cv[0] = g_engfuncs.pfnCVarGetPointer("zevo_pc_models");
	p_cv[1] = g_engfuncs.pfnCVarGetPointer("zevo_pc_sounds");
	p_cv[2] = g_engfuncs.pfnCVarGetPointer("zevo_pc_generic");
	p_cv[3] = g_engfuncs.pfnCVarGetPointer("zevo_pc_total");
	p_cvAuto = g_engfuncs.pfnCVarGetPointer("zevo_pc_autolist");
}

static void SetCv(cvar_t *cv, int v)
{
	if (!cv) return;
	char b[16];
	snprintf(b, sizeof(b), "%d", v);
	g_engfuncs.pfnCvar_DirectSet(cv, b);
}

static void UpdateCvars()
{
	SetCv(p_cv[0], g_resCount[RT_MODEL]);
	SetCv(p_cv[1], g_resCount[RT_SOUND]);
	SetCv(p_cv[2], g_resCount[RT_GENERIC]);
	SetCv(p_cv[3], g_resCount[RT_MODEL] + g_resCount[RT_SOUND] + g_resCount[RT_GENERIC]);
}

// ------------------------------------------------------------- hunk numbers
static long long g_trackedBytes = 0;                     // estimate if probe fails
static const long long g_fallbackMax = 64LL * 1024 * 1024;

static void GetHunk(long long &max, long long &low, long long &high)
{
	if (g_probeOk) {
		max = *p_hunk_size; low = *p_hunk_low_used; high = *p_hunk_high_used;
	} else {
		max = g_fallbackMax; low = g_trackedBytes; high = 0;
	}
}

static const char *MapName()
{
	return gpGlobals ? STRING(gpGlobals->mapname) : "";
}

static void PrintBlock()
{
	long long max, low, high;
	GetHunk(max, low, high);
	long long used = low + high;
	if (used > max) used = max;
	long long fr = max - used;
	Out(TAG "========================================\n");
	Out(TAG "Cache/Hunk Memory%s\n", g_probeOk ? "" : "  (ESTIMATE - engine hunk symbols not found)");
	Out(TAG "Max:       %lld KB (%.2f MB)\n", KB(max), MB(max));
	Out(TAG "Used:      %lld KB (%.2f MB)\n", KB(used), MB(used));
	Out(TAG "Free:      %lld KB (%.2f MB)\n", KB(fr), MB(fr));
	Out(TAG "Remaining: %.2f%%\n", max ? 100.0 * fr / max : 0.0);
	Out(TAG "Low Hunk:  %lld KB\n", KB(low));
	Out(TAG "High Hunk: %lld KB\n", KB(high));
	Out(TAG "Models:    %d/%d\n", g_resCount[RT_MODEL], ENGINE_LIMIT);
	Out(TAG "Sounds:    %d/%d\n", g_resCount[RT_SOUND], ENGINE_LIMIT);
	Out(TAG "Generic:   %d/%d\n", g_resCount[RT_GENERIC], ENGINE_LIMIT);
	Out(TAG "========================================\n");
}

static void PrintFailure(long long requested, const char *resource)
{
	long long max, low, high;
	GetHunk(max, low, high);
	long long used = low + high;
	if (used > max) used = max;
	long long fr = max - used;
	Out(TAG "!!! CACHE ALLOCATION FAILURE !!!\n");
	Out(TAG "Map:       %s\n", MapName());
	Out(TAG "Resource:  %s\n", resource);
	Out(TAG "Requested: %lld KB (%.2f MB)\n", KB(requested), MB(requested));
	Out(TAG "Max:       %lld KB (%.2f MB)\n", KB(max), MB(max));
	Out(TAG "Used:      %lld KB (%.2f MB)\n", KB(used), MB(used));
	Out(TAG "Free:      %lld KB (%.2f MB)\n", KB(fr), MB(fr));
	Out(TAG "Remaining: %.2f%%\n", max ? 100.0 * fr / max : 0.0);
	Out(TAG "Low Hunk:  %lld KB\n", KB(low));
	Out(TAG "High Hunk: %lld KB\n", KB(high));
}

static void PrintLimit(int type, const char *name, bool over)
{
	Out(TAG "%s\n", over ? "!!! PRECACHE LIMIT EXCEEDED !!!" : "PRECACHE LIMIT WARNING (90%)");
	Out(TAG "Map:       %s\n", MapName());
	Out(TAG "Type:      %s\n", g_typeName[type]);
	Out(TAG "Count:     %d/%d\n", g_resCount[type], ENGINE_LIMIT);
	Out(TAG "Resource:  %s\n", name);
	if (type == RT_MODEL)
		Out(TAG "Note:      the map's own brush models (*1, *2, ...) also use model slots.\n");
	if (over)
		Out(TAG "Note:      the engine will refuse this resource - remove/merge precaches.\n");
}

// ------------------------------------------------------------ per-map state
static char g_lastMap[64];
static int g_warnLevel;            // 0 none, 1 <15%, 2 <10%, 3 <5%
static bool g_verbose = false;
static char g_lastResource[256];
static long long g_lastRequested;

static long long ResourceSize(const char *prefix, const char *name)
{
	char path[512];
	const char *dirs[2] = { g_gameDir, "valve" };
	for (int i = 0; i < 2; i++) {
		snprintf(path, sizeof(path), "%s/%s%s", dirs[i], prefix, name);
		FILE *f = fopen(path, "rb");
		if (f) {
			long long sz = 0;
			if (fseek(f, 0, SEEK_END) == 0) sz = ftell(f);
			fclose(f);
			return sz > 0 ? sz : 0;
		}
	}
	return 0;
}

static void CheckNewMap()
{
	const char *map = MapName();
	if (strncmp(g_lastMap, map, sizeof(g_lastMap)) == 0) return;
	strncpy(g_lastMap, map, sizeof(g_lastMap) - 1);
	g_lastMap[sizeof(g_lastMap) - 1] = 0;
	memset(g_seen, 0, sizeof(g_seen));
	memset(g_resCount, 0, sizeof(g_resCount));
	memset(g_limitState, 0, sizeof(g_limitState));
	g_trackedBytes = 0;
	g_warnLevel = 0;
	g_lastResource[0] = 0;
	UpdateCvars();
	Out(TAG "Map: %s - precache started\n", map);
	PrintBlock();
}

static void CheckLowWater()
{
	long long max, low, high;
	GetHunk(max, low, high);
	if (max <= 0) return;
	double rem = 100.0 * (max - low - high) / max;
	int lvl = rem < 5.0 ? 3 : rem < 10.0 ? 2 : rem < 15.0 ? 1 : 0;
	if (lvl > g_warnLevel) {
		g_warnLevel = lvl;
		Out(TAG "LOW MEMORY: remaining below %d%% (last resource: %s)\n",
			lvl == 3 ? 5 : lvl == 2 ? 10 : 15, g_lastResource);
		PrintBlock();
	}
}

static void OnPrecache(int type, const char *prefix, const char *name)
{
	if (!name || !*name) return;
	if (type == RT_MODEL && *name == '*') return;     // brush model reference
	CheckNewMap();
	if (!SeenInsert(type, name)) return;

	long long size = ResourceSize(prefix, name);
	g_trackedBytes += size;

	int idx = g_resCount[type]++;
	if (idx < MAX_RES) {
		strncpy(g_res[type][idx].name, name, sizeof(g_res[type][idx].name) - 1);
		g_res[type][idx].name[sizeof(g_res[type][idx].name) - 1] = 0;
		g_res[type][idx].size = size;
	}
	UpdateCvars();

	strncpy(g_lastResource, name, sizeof(g_lastResource) - 1);
	g_lastResource[sizeof(g_lastResource) - 1] = 0;
	g_lastRequested = size;

	long long max, low, high;
	GetHunk(max, low, high);
	long long fr = max - low - high;

	if (g_verbose)
		Out(TAG "CACHE REQUEST  %lld bytes  free %lld bytes  %s\n", size, fr, name);

	// engine slot limit
	if (g_resCount[type] > ENGINE_LIMIT) {
		if (g_limitState[type] < 2) { g_limitState[type] = 2; PrintLimit(type, name, true); }
	} else if (g_resCount[type] >= WARN_AT) {
		if (g_limitState[type] < 1) { g_limitState[type] = 1; PrintLimit(type, name, false); }
	}

	// hunk memory
	if (size > 0 && size > fr) {
		PrintFailure(size, name);
		return;
	}
	CheckLowWater();
}

// ------------------------------------------------------ engine function hooks
static int pfnPrecacheModel(const char *s)   { OnPrecache(RT_MODEL,   "",       s); RETURN_META_VALUE(MRES_IGNORED, 0); }
static int pfnPrecacheSound(const char *s)   { OnPrecache(RT_SOUND,   "sound/", s); RETURN_META_VALUE(MRES_IGNORED, 0); }
static int pfnPrecacheGeneric(const char *s) { OnPrecache(RT_GENERIC, "",       s); RETURN_META_VALUE(MRES_IGNORED, 0); }

static enginefuncs_t g_zevoEngTable;

C_DLLEXPORT int GetEngineFunctions(enginefuncs_t *pengfuncsFromEngine, int *interfaceVersion)
{
	if (!pengfuncsFromEngine) return FALSE;
	if (*interfaceVersion != ENGINE_INTERFACE_VERSION) {
		*interfaceVersion = ENGINE_INTERFACE_VERSION;
		return FALSE;
	}
	memset(&g_zevoEngTable, 0, sizeof(g_zevoEngTable));
	g_zevoEngTable.pfnPrecacheModel   = pfnPrecacheModel;
	g_zevoEngTable.pfnPrecacheSound   = pfnPrecacheSound;
	g_zevoEngTable.pfnPrecacheGeneric = pfnPrecacheGeneric;
	memcpy(pengfuncsFromEngine, &g_zevoEngTable, sizeof(enginefuncs_t));
	return TRUE;
}

// ------------------------------------------------------------- list / top
static void Emit(FILE *f, const char *s)
{
	if (f) fputs(s, f);
	else g_engfuncs.pfnServerPrint(s);
}

static void ListType(int type, FILE *f)
{
	char line[256];
	int n = g_resCount[type] < MAX_RES ? g_resCount[type] : MAX_RES;
	long long total = 0;

	snprintf(line, sizeof(line), "---- %s: %d/%d ----\n", g_typeName[type], g_resCount[type], ENGINE_LIMIT);
	Emit(f, line);
	for (int i = 0; i < n; i++) {
		total += g_res[type][i].size;
		snprintf(line, sizeof(line), "%4d  %10lld  %s\n", i + 1, g_res[type][i].size, g_res[type][i].name);
		Emit(f, line);
	}
	snprintf(line, sizeof(line), "---- %s size on disk: %lld KB (%.2f MB)\n", g_typeName[type], KB(total), MB(total));
	Emit(f, line);
}

static bool SaveListFile(int mask, char *outPath, size_t sz)
{
	const char *map = g_lastMap[0] ? g_lastMap : MapName();
	char safe[64];
	size_t i = 0;
	for (; map[i] && i < sizeof(safe) - 1; i++) {
		char c = map[i];
		safe[i] = ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') ? c : '_';
	}
	safe[i] = 0;
	if (!safe[0]) strcpy(safe, "unknown");

	snprintf(outPath, sz, "%s/addons/zevo_memory/precache_%s.txt", g_gameDir, safe);
	FILE *f = fopen(outPath, "w");
	if (!f) return false;
	fprintf(f, "# ZEVO MEMORY precache list - map %s\n# columns: #  size-on-disk(bytes)  resource\n\n", map);
	for (int t = 0; t < RT_COUNT; t++) {
		if (!(mask & (1 << t))) continue;
		ListType(t, f);
		fputc('\n', f);
	}
	fclose(f);
	return true;
}

// zevo_list [models|sounds|generic|all] [file]
static void CmdList()
{
	int argc = g_engfuncs.pfnCmd_Argc();
	int mask = 7;
	bool toFile = false;
	for (int i = 1; i < argc; i++) {
		const char *a = g_engfuncs.pfnCmd_Argv(i);
		if (!strcasecmp(a, "models")) mask = 1;
		else if (!strcasecmp(a, "sounds")) mask = 2;
		else if (!strcasecmp(a, "generic")) mask = 4;
		else if (!strcasecmp(a, "all")) mask = 7;
		else if (!strcasecmp(a, "file")) toFile = true;
		else { Con(TAG "usage: zevo_list [models|sounds|generic|all] [file]\n"); return; }
	}
	Con(TAG "Map: %s   Models %d/%d   Sounds %d/%d   Generic %d/%d\n", g_lastMap[0] ? g_lastMap : MapName(),
		g_resCount[RT_MODEL], ENGINE_LIMIT, g_resCount[RT_SOUND], ENGINE_LIMIT, g_resCount[RT_GENERIC], ENGINE_LIMIT);
	if (toFile) {
		char path[512];
		if (SaveListFile(mask, path, sizeof(path))) Con(TAG "list written to %s\n", path);
		else Con(TAG "could not write list file (%s)\n", path);
		return;
	}
	for (int t = 0; t < RT_COUNT; t++)
		if (mask & (1 << t)) ListType(t, NULL);
}

// zevo_top [n]
static void CmdTop()
{
	int n = 20;
	if (g_engfuncs.pfnCmd_Argc() >= 2) {
		const char *a = g_engfuncs.pfnCmd_Argv(1);
		int v = 0;
		for (; *a >= '0' && *a <= '9'; a++) v = v * 10 + (*a - '0');
		if (v > 0) n = v;
	}
	if (n > 200) n = 200;

	static unsigned char used[RT_COUNT][MAX_RES];
	memset(used, 0, sizeof(used));
	long long all = 0;
	for (int t = 0; t < RT_COUNT; t++) {
		int cnt = g_resCount[t] < MAX_RES ? g_resCount[t] : MAX_RES;
		for (int i = 0; i < cnt; i++) all += g_res[t][i].size;
	}
	Con(TAG "Top %d biggest precached files (map %s, total on disk %.2f MB)\n", n,
		g_lastMap[0] ? g_lastMap : MapName(), MB(all));
	for (int k = 0; k < n; k++) {
		int bt = -1, bi = -1;
		long long bs = 0;
		for (int t = 0; t < RT_COUNT; t++) {
			int cnt = g_resCount[t] < MAX_RES ? g_resCount[t] : MAX_RES;
			for (int i = 0; i < cnt; i++)
				if (!used[t][i] && g_res[t][i].size > bs) { bs = g_res[t][i].size; bt = t; bi = i; }
		}
		if (bt < 0) break;
		used[bt][bi] = 1;
		Con("%3d. %10lld bytes (%8.2f KB)  %-7s %s\n", k + 1, bs, (double)bs / 1024.0, g_typeName[bt], g_res[bt][bi].name);
	}
}

// ---------------------------------------------------------- game DLL (post)
static void ServerActivate_Post(edict_t *, int, int)
{
	CheckNewMap();
	Out(TAG "Map: %s - precache finished\n", MapName());
	PrintBlock();
	if (p_cvAuto && p_cvAuto->value != 0.0f) {
		char path[512];
		if (SaveListFile(7, path, sizeof(path))) Out(TAG "precache list saved: %s\n", path);
	}
	RETURN_META(MRES_IGNORED);
}

static void ServerDeactivate_Post()
{
	g_lastMap[0] = 0;              // so a reload of the same map is treated as new
	RETURN_META(MRES_IGNORED);
}

static DLL_FUNCTIONS g_zevoDllTable;

C_DLLEXPORT int GetEntityAPI2_Post(DLL_FUNCTIONS *pFunctionTable, int *interfaceVersion)
{
	if (!pFunctionTable) return FALSE;
	if (*interfaceVersion != INTERFACE_VERSION) {
		*interfaceVersion = INTERFACE_VERSION;
		return FALSE;
	}
	memset(&g_zevoDllTable, 0, sizeof(g_zevoDllTable));
	g_zevoDllTable.pfnServerActivate   = ServerActivate_Post;
	g_zevoDllTable.pfnServerDeactivate = ServerDeactivate_Post;
	memcpy(pFunctionTable, &g_zevoDllTable, sizeof(DLL_FUNCTIONS));
	return TRUE;
}

// ------------------------------------------------------------ server command
static void CmdZevoMemory()
{
	if (g_engfuncs.pfnCmd_Argc() >= 2 && strcmp(g_engfuncs.pfnCmd_Argv(1), "verbose") == 0) {
		g_verbose = g_engfuncs.pfnCmd_Argc() >= 3 ? (g_engfuncs.pfnCmd_Argv(2)[0] != '0') : !g_verbose;
		Out(TAG "verbose logging of every resource: %s\n", g_verbose ? "ON" : "OFF");
		return;
	}
	Out(TAG "Map: %s\n", MapName());
	PrintBlock();
}

// If the process exits right after a near-full hunk, leave a trace in the log.
// (Runs on normal exit() paths only; a hard abort() cannot be caught.)
__attribute__((destructor)) static void ZevoFini()
{
	if (!g_probeOk || !g_lastResource[0] || !g_logPath[0]) return;
	long long max, low, high;
	GetHunk(max, low, high);
	if (max <= 0 || 100.0 * (max - low - high) / max >= 15.0) return;
	FILE *f = fopen(g_logPath, "a");
	if (!f) return;
	fprintf(f, TAG "SERVER EXITING with %.2f%% hunk remaining. Last resource: %s (%lld KB)\n",
		100.0 * (max - low - high) / max, g_lastResource, KB(g_lastRequested));
	fclose(f);
}

// --------------------------------------------------------------- Metamod API
static META_FUNCTIONS gMetaFunctionTable =
	{ NULL, NULL, NULL, GetEntityAPI2_Post, NULL, NULL, GetEngineFunctions, NULL };

C_DLLEXPORT void WINAPI GiveFnptrsToDll(enginefuncs_t *pengfuncsFromEngine, globalvars_t *pGlobals)
{
	memcpy(&g_engfuncs, pengfuncsFromEngine, sizeof(enginefuncs_t));
	gpGlobals = pGlobals;
}

C_DLLEXPORT int Meta_Query(char *, plugin_info_t **pPlugInfo, mutil_funcs_t *pMetaUtilFuncs)
{
	*pPlugInfo = &Plugin_info;
	gpMetaUtilFuncs = pMetaUtilFuncs;
	return TRUE;
}

C_DLLEXPORT int Meta_Attach(PLUG_LOADTIME, META_FUNCTIONS *pFunctionTable,
                            meta_globals_t *pMGlobals, gamedll_funcs_t *pGamedllFuncs)
{
	if (!pMGlobals || !pFunctionTable) return FALSE;
	gpMetaGlobals = pMGlobals;
	gpGamedllFuncs = pGamedllFuncs;
	memcpy(pFunctionTable, &gMetaFunctionTable, sizeof(META_FUNCTIONS));

	// <gamedir>/addons/zevo_memory/  (created if missing)
	g_gameDir[0] = 0;
	g_engfuncs.pfnGetGameDir(g_gameDir);
	g_gameDir[sizeof(g_gameDir) - 1] = 0;
	if (!g_gameDir[0]) strcpy(g_gameDir, "cstrike");
	char dir[512];
	snprintf(dir, sizeof(dir), "%s/addons", g_gameDir);
	mkdir(dir, 0755);
	snprintf(dir, sizeof(dir), "%s/addons/zevo_memory", g_gameDir);
	mkdir(dir, 0755);
	snprintf(g_logPath, sizeof(g_logPath), "%s/addons/zevo_memory/zevo_memory.log", g_gameDir);

	RegisterCvars();
	ProbeHunk();
	g_engfuncs.pfnAddServerCommand("zevo_memory", CmdZevoMemory);
	g_engfuncs.pfnAddServerCommand("zevo_list", CmdList);
	g_engfuncs.pfnAddServerCommand("zevo_top", CmdTop);

	if (g_probeOk)
		Out(TAG "v1.2 loaded - hunk counters found in %s (max %lld KB)\n", g_enginePath, KB(*p_hunk_size));
	else
		Out(TAG "v1.2 loaded - hunk counters NOT found (engine: %s). Using estimate. Hunk-like symbols: %s\n",
			g_enginePath[0] ? g_enginePath : "not located", g_hunkNames[0] ? g_hunkNames : "(none)");
	return TRUE;
}

C_DLLEXPORT int Meta_Detach(PLUG_LOADTIME, PL_UNLOAD_REASON)
{
	return TRUE;
}
