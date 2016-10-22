# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000053 - The system must be configured to prevent the storage of passwords and credentials.'

control 'WN12-SO-000053' do
  impact 0.5
  title 'The system must be configured to prevent the storage of passwords and credentials.'
  desc '
This setting controls the storage of passwords and credentials for network authentication on the local system.  Such credentials must not be stored on the local machine, as that may lead to account compromise.
'
  tag 'stig','WN12-SO-000053'
  tag severity: 'medium'
  tag checkid: 'C-WN12-SO-000053_chk'
  tag fixid: 'F-WN12-SO-000053_fix'
  tag version: 'WN12-SO-000053'
  tag ruleid: 'WN12-SO-000053_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Do not allow storage of passwords and credentials for network authentication" to "Enabled".
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa\

Value Name: DisableDomainCreds

Value Type: REG_DWORD
Value: 1
'

# START_DESCRIBE WN12-SO-000053
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000053

end
