# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000008 - Permissions for Windows installation directory must conform to minimum requirements.'

control 'WN12-GE-000008' do
  impact 0.5
  title 'Permissions for Windows installation directory must conform to minimum requirements.'
  desc '
Changing the system\'s file and directory permissions allows the possibility of unauthorized and anonymous modification to the operating system and installed applications.

The default permissions are adequate when the Security Option "Network access: Let everyone permissions apply to anonymous users" is set to "Disabled" (V-3377).
'
  tag 'stig','WN12-GE-000008'
  tag severity: 'medium'
  tag checkid: 'C-WN12-GE-000008_chk'
  tag fixid: 'F-WN12-GE-000008_fix'
  tag version: 'WN12-GE-000008'
  tag ruleid: 'WN12-GE-000008_rule'
  tag fixtext: '
Maintain the default file ACLs and configure the Security Option: "Network access: Let everyone permissions apply to anonymous users" to "Disabled" (V-3377).

Default Permissions:
Type - "Allow" for all
Inherited from - "None" for all

Principal - Access - Applies to

TrustedInstaller - Full control - This folder and subfolders
SYSTEM - Modify - This folder only
SYSTEM - Full control - Subfolders and files only
Administrators - Modify - This folder only
Administrators - Full control - Subfolders and files only
Users - Read & execute - This folder, subfolders and files
CREATOR OWNER - Full control - Subfolders and files only
ALL APPLICATION PACKAGES - Read & execute - This folder, subfolders and files
'
  tag checktext: '
The default permissions are adequate when the Security Option "Network access: Let everyone permissions apply to anonymous users" is set to "Disabled" (V-3377).  If the default ACLs are maintained and the referenced option is set to "Disabled", this is not a finding.

Verify the default permissions for the Windows installation directory (usually C:\Windows).  Nonprivileged groups such as Users or Authenticated Users must not have greater than Read & execute permissions except where noted as defaults.  (Individual accounts must not be used to assign permissions.)

Viewing in File Explorer:
View the Properties of the folder.
Select the "Security" tab, and the "Advanced" button.

Default Permissions:
\Windows
Type - "Allow" for all
Inherited from - "None" for all

Principal - Access - Applies to

TrustedInstaller - Full control - This folder and subfolders
SYSTEM - Modify - This folder only
SYSTEM - Full control - Subfolders and files only
Administrators - Modify - This folder only
Administrators - Full control - Subfolders and files only
Users - Read & execute - This folder, subfolders and files
CREATOR OWNER - Full control - Subfolders and files only
ALL APPLICATION PACKAGES - Read & execute - This folder, subfolders and files


Alternately, use Icacls:

Open a Command prompt (admin).
Enter icacls followed by the directory:

icacls c:\windows

The following results should be displayed:

c:\windows
NT SERVICE\TrustedInstaller:(F)
NT SERVICE\TrustedInstaller:(CI)(IO)(F)
NT AUTHORITY\SYSTEM:(M)
NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
BUILTIN\Administrators:(M)
BUILTIN\Administrators:(OI)(CI)(IO)(F)
BUILTIN\Users:(RX)
BUILTIN\Users:(OI)(CI)(IO)(GR,GE)
CREATOR OWNER:(OI)(CI)(IO)(F)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
Successfully processed 1 files; Failed processing 0 files
'

# START_DESCRIBE WN12-GE-000008
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000008

end
