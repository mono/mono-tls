thisdir = class/Mono.Security.Providers/NewMonoSource
SUBDIRS = 
include ../../../build/rules.make

LIBRARY = Mono.Security.Providers.NewMonoSource.dll
LIB_MCS_FLAGS = -r:System.dll -d:SECURITY_DEP -d:MONO_SECURITY_ALIAS -r:MonoSecurity=Mono.Security \
	-unsafe -nowarn:1030 -keyfile:../../mono.pub -delaysign \
	-d:MONO -d:FEATURE_PAL -d:MONO_FEATURE_NEW_TLS -d:NEW_MONO_SOURCE -d:DISABLE_CAS_USE
TEST_MCS_FLAGS = $(LIB_MCS_FLAGS) -nowarn:169,219,618,672

include ../../../build/library.make

