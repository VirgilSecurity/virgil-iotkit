#!/usr/bin/python

# Includes
import configparser
import os
import sys
import inspect

Import("env")

# Configuration file
filename = inspect.getframeinfo(inspect.currentframe()).filename
path = os.path.dirname(os.path.abspath(filename))
configfile = path + "/virgil-iotkit.ini"
config = configparser.ConfigParser()

#GlobalBuildFlags = ['-DINFO_SERVER=1', '-DPRVS_SERVER=1', '-DGATEWAY=1']

#print("############################### PRINT ENV #################################")
#print(env)
#print("############################### DUMP ENV #################################")
#print(env.Dump())
#print("###########################################################################")


# Reading init file
# ****************************************************************************
def OptionFileRead():
    if os.path.exists(configfile):
        print("Reading configuration")
        config.read(configfile)
    else:
        return -1
    return 0


# Read param from section
# ****************************************************************************
def OptionValueRead(OptSection, OptParam):
    if not config.has_section(OptSection):
        return None
    if not config.has_option(OptSection, OptParam):
        return None
    return config.get(OptSection, OptParam)


# while defines
# ****************************************************************************
def ProceedDefines(GlobalDefines):
    EnabledDefines = []
    print("virgil-iotkit: Find enabled defines")
    print("virgil-iotkit: Define string [%s]" % GlobalDefines)
    for DefineItem in GlobalDefines:
        if DefineItem[0:2] == "-D":
           SplitedDefines = DefineItem[2:].split('=')
           EnabledDefines.append(SplitedDefines[0])
    if len(EnabledDefines) > 0:
        print("virgil-iotkit: Defines found - [%s]" % EnabledDefines)
    return EnabledDefines


# Add sources by sections
# ****************************************************************************
def AddSourceFilters(DefineList):
    SourceFiles = []
    print("virgil-iotkit: Find sources")
    for DefineItem in DefineList:
        SectionSourceFiles = OptionValueRead(DefineItem, "files")
        if SectionSourceFiles:
            SectionSourceFiles = SectionSourceFiles.strip('\n').replace(" ", "").split(",")
            for FilesItem in SectionSourceFiles:
                PrepFileStr = "+<%s>" % FilesItem
                if not (PrepFileStr in SourceFiles):
                    SourceFiles.append(PrepFileStr)
                    print("virgil-ikit: Add source [%s]" % PrepFileStr)
    return SourceFiles


# while defines and call find depends
# ****************************************************************************
def ProceedDepends(defines):
    FullDefines = []
    FullDefines.extend(defines)
    print("virgil-iotkit: Searching depends defines")
    for DefineItem in FullDefines:
        Depends = OptionValueRead(DefineItem, "deps")
        if Depends:
            Depends = Depends.strip('\n').replace(" ", "").split(",")
            for DependItem in Depends:
                if not (DependItem in FullDefines):
                    FullDefines.append(DependItem)
                    print("virgil-iotkit: Add define [%s]" % DependItem)
    return FullDefines

# Prepare src filter
# ****************************************************************************
def PrepareSrcFilter(SrcFilters):
    print("virgil-iotkit: Replace src_filter [%s]" % SrcFilters)
    env.Replace(SRC_FILTER=SrcFilters)

# Get  build flags
# ****************************************************************************
def GetBuildFlags():
    BuildFlags = []
    if "BUILD_FLAGS" in env:
       BuildFlags = env["BUILD_FLAGS"]
       return BuildFlags
    return None
       
# main func
# ****************************************************************************
def Main():
    GlobalBuildFlags = []
    GlobalBuildFlags = GetBuildFlags()
    if len(GlobalBuildFlags) < 1:
        return 0
    if OptionFileRead() < 0:
        print("ERROR: Configuration file [%s] not found." % config)
        return -1
    defines = ProceedDefines(GlobalBuildFlags)
    if not defines:
        print("virgil-iotkit: Defines not found. exit 0")
        return 0
    FullDependDefines = ProceedDepends(defines)
    SrcFilters = AddSourceFilters(FullDependDefines)
    if SrcFilters:
        PrepareSrcFilter(SrcFilters)

    return 0
# ****************************************************************************

Main()



# print("############################### PRINT ENV #################################")
# print(env)
# print("############################### DUMP ENV #################################")
# print(env.Dump())
# print("###########################################################################")

