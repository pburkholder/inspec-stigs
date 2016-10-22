# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000041 - The system must be configured to limit how often keep-alive packets are sent.'

control 'WN12-SO-000041' do
  impact 0.1
  title 'The system must be configured to limit how often keep-alive packets are sent.'
  desc '
This setting controls how often TCP sends a keep-alive packet in attempting to verify that an idle connection is still intact.  A higher value could allow an attacker to cause a denial of service with numerous connections.
'
  tag 'stig','WN12-SO-000041'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000041_chk'
  tag fixid: 'F-WN12-SO-000041_fix'
  tag version: 'WN12-SO-000041'
  tag ruleid: 'WN12-SO-000041_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds" to "300000 or 5 minutes (recommended)" or less.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system\'s policy tools.)
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\Tcpip\Parameters\

Value Name: KeepAliveTime

Value Type: REG_DWORD
Value: 300000 (or less)
'

# START_DESCRIBE WN12-SO-000041
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000041

end
