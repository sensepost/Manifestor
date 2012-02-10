#!/usr/bin/env python
# -*- coding: UTF-8 -*-

"""
This utility extracts AndroidManifest.xml file from an apk, converts it into
human readable format and stores in on your hard disk.  Additionally, it scans
the AndroidManifest.xml file for grant-uri-permission tag
(http://developer.android.com/guide/topics/manifest/grant-uri-permission-element.html)
and attempts to determine if it is possible for any other installed application
to steal data of target content-provider.  In order to use this utility, your
android phone should be rooted and have a find command (via busybox or
terminal)
"""

import os
import re
import subprocess
import sys


AAPT_BIN = 'aapt'
ADB_BIN = 'adb'


def find_apks(path):
    #TODO: Implement this
    proc = subprocess.Popen(
        [ADB_BIN, 'shell', 'find', path, '-name', '*.apk'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = proc.communicate()
    return [line.strip() for line in stdout.split('\n') if line.strip()]


def check_manifest(apk_path, outdir):
    apk_name = os.path.split(apk_path)[-1]

    print "Extracting Manifest file..."
    manifestfilename = os.path.join(outdir, 'Manifest_%s.txt' % (apk_name))
    proc = subprocess.Popen(
        [AAPT_BIN, "d", "xmltree", apk_path, "AndroidManifest.xml"],
        stdout=subprocess.PIPE
    )
    stdoutdata, stderrdata = proc.communicate()
    open(manifestfilename, 'w').write(stdoutdata)

    print 'The AndroidManifest.xml for %s has been saved at location: %s' %(
        apk_name, manifestfilename
    )

    print "Scanning for excessive permissions..."
    grant_path = re.findall(
        r'grant-uri-permission.*?\n.*?path(|Pattern|Prefix)\([0-9a-fx]*\)="(.*?)"',
        stdoutdata, re.MULTILINE
    )
    print "Found %d instances of grant-uri-permission" % (len(grant_path))
    for count, i in enumerate(grant_path):
        if i[1] == '/':
            print '(%s) Instance %d looks vulnerable. It may be possible for any app to query data of this content provider.' % (i[1], count+1)
        else:
            print "(%s) Instance %d looks good. Its worth analysing the AndroidManifest.xml manually" % (i[1], count+1)


def download_apk(apk_path, outdir):
    """Downloads an APK from the given Android device path to the given output
        directory.
        @returns: The path on the local file system to the downloaded APK."""
    print "Downloading apk %s..." % (apk_path)
    exit_status = subprocess.call(
        [ADB_BIN, "pull", apk_path, outdir],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if exit_status == 1:
        print "Looks like the device is not connected. Please connect your android device via usb and enable usb debugging"
        sys.exit(1)
    else:
        print "The apk has been saved to: %s" % (os.path.abspath(outdir))

    apk_local = os.path.join(outdir, os.path.split(apk_path)[-1])
    if not os.path.isfile(apk_local):
        raise IOError('APK downloaded, but doesn not exist: %s' % (apk_local))
    return apk_local


def main(options, args):
    """Main entry point.
        @type  options: optparse.Values
        @param options: Options parsed from the command-line.
        @type  args: list
        @param args: Residual arguments not parsed by the option parser."""
    if len(options.apks) == 1 and options.apks[0].lower() == 'scan_all':
        download_apks = find_apks('/system/app') + find_apks('/system/sd/app')
    else:
        download_apks = list(options.apks)
        for apkpath in options.apkpaths:
            download_apks.extend(find_apks(apkpath))

    all_apks = []

    for apk in download_apks:
        all_apks.append(download_apk(apk, options.outputdir))

    all_apks.extend(options.localfiles)

    for apk in all_apks:
        check_manifest(apk, options.outputdir)


def create_option_parser():
    from optparse import OptionParser
    parser = OptionParser(usage='%prog [<options>]\nSaurabh Harit, SensePost')

    parser.add_option(
        '-o', '--output-dir', dest='outputdir', default=os.path.curdir,
        help='Output directory to use. This path will be used to download the apk files to your machine',
    )
    parser.add_option(
        '-a', '--apk', dest='apks', action='append', default=[],
        help='Path (on Android device) of APK(s) to scan. Example: /system/app/Gmail.apk. If the value of this switch is set to scan_all, the script will automatically scan all apks in /system/app and /system/sd/app folder'
    )
    parser.add_option(
        '-l', '--local', dest='localfiles', action='append', default=[],
        help='Path (on the local machine) to APK(s).'
    )
    parser.add_option(
        '-A', '--apkpath', dest='apkpaths', action='append', default=[],
        help='Path (on Android device) to search for APK(s) to scan. Example: /system/app'
    )

    return parser


if __name__ == '__main__':
    parser = create_option_parser()
    options, args = parser.parse_args()
    if not os.path.isdir(options.outputdir):
        parser.error('Invalid output directory: %s' % (options.outputdir))
    if not options.apks and not options.apkpaths and not options.localfiles:
        parser.error('No APKs or APK paths specified.')
    main(options, args)
