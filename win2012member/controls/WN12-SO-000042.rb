# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000042 - IPSec exemptions must be limited.'

control 'WN12-SO-000042' do
  impact 0.1
  title 'IPSec exemptions must be limited.'
  desc '
IPSec exemption filters allow specific traffic that may be needed by the system  for such things as Kerberos  authentication.  This setting configures Windows for specific IPSec exemptions.
'
  tag 'stig','WN12-SO-000042'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000042_chk'
  tag fixid: 'F-WN12-SO-000042_fix'
  tag version: 'WN12-SO-000042'
  tag ruleid: 'WN12-SO-000042_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (NoDefaultExempt) Configure IPSec exemptions for various types of network traffic" to "Only ISAKMP is exempt (recommended for Windows Server 2003)".

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system\'s policy tools.)
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\IPSEC\

Value Name: NoDefaultExempt

Value Type: REG_DWORD
Value: 3
'

# START_DESCRIBE WN12-SO-000042
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000042

end
