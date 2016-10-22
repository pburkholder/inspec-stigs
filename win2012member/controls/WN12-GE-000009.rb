# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000009 - Password complexity software that enforces DoD requirements must be implemented.'

control 'WN12-GE-000009' do
  impact 0.5
  title 'Password complexity software that enforces DoD requirements must be implemented.'
  desc '
Password complexity software (e.g., Password Policy Enforcer) enforces a minimum mix of character types and potentially other options to create strong passwords. 

Passwords must contain a case-sensitive character mix with at least one of each of the following:  uppercase letters, lowercase letters, numbers, and special characters.

Sites are responsible for installing password complexity software that complies with current DoD requirements.
'
  tag 'stig','WN12-GE-000009'
  tag severity: 'medium'
  tag checkid: 'C-WN12-GE-000009_chk'
  tag fixid: 'F-WN12-GE-000009_fix'
  tag version: 'WN12-GE-000009'
  tag ruleid: 'WN12-GE-000009_rule'
  tag fixtext: '
Install password complexity software and configure it to enforce the required DoD standards of a case sensitive mix of at least one of each of uppercase letters, lowercase letters, numbers, and special characters.

If the enpasflt password filter is used:

-Copy the appropriate version to %systemroot%\system32.
-Add the file name (e.g., "EnPasFltV2x86") to the "Notification Packages" value under registry key "HKLM\System\CurrentControlSet\Control\LSA".
-Restart the system.
'
  tag checktext: '
Verify password complexity software that requires a case-sensitive character mix of at least one of each of uppercase letters, lowercase letters, numbers, and special characters is installed and enforced .

The enpasflt password filter is available as an option on the IASE website in the Windows Support Files area (PKI required - http://iase.disa.mil/stigs/os/windows/support_files.html).  It must be tested for the particular environment.  If it does not function properly or causes issues, the site will be responsible for obtaining other password complexity software to meet the requirements.

The current available versions are:

Name - Modified Date
EnPasFltV2x86.dll - 3/21/2011
EnPasFltV2x64.dll - 3/21/2011

If another product, such as PPE, or a different version of enpasflt is used, the SA must demonstrate that it is configured to enforce the DoD requirements.

For the enpasflt password filter to function properly, verify the following:

-The appropriate version of the file will be located in %systemroot%\system32.
-The Date Modified should be 3/21/2011.
-The "Notification Packages" value under registry key "HKLM\System\CurrentControlSet\Control\LSA" must include the file name (e.g., "EnPasFltV2x86").

Severity Override:  If no password filter is used, and the security option for "Password must meet complexity requirements" (V-1150) is set to "Enabled", this finding can be downgraded to a CAT III, as a less strict complexity algorithm is used.

Note: If a password filter is not used, the site is still responsible for requiring full compliance with DoD policy, even though the password complexity setting does not enforce the 4-character type rule.
'

# START_DESCRIBE WN12-GE-000009
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000009

end
