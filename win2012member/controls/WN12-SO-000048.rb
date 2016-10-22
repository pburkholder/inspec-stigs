# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-SO-000048 - The system must limit how many times unacknowledged TCP data is retransmitted.'

control 'WN12-SO-000048' do
  impact 0.1
  title 'The system must limit how many times unacknowledged TCP data is retransmitted.'
  desc '
In a SYN flood attack, the attacker sends a continuous stream of SYN packets to a server, and the server leaves the half-open connections open until it is overwhelmed and is no longer able to respond to legitimate requests.
'
  tag 'stig','WN12-SO-000048'
  tag severity: 'low'
  tag checkid: 'C-WN12-SO-000048_chk'
  tag fixid: 'F-WN12-SO-000048_fix'
  tag version: 'WN12-SO-000048'
  tag ruleid: 'WN12-SO-000048_rule'
  tag fixtext: '
Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is the default)" to "3" or less.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system\'s policy tools.)
'
  tag checktext: '
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\Tcpip\Parameters\

Value Name: TcpMaxDataRetransmissions

Value Type: REG_DWORD
Value: 3 (or less)
'

# START_DESCRIBE WN12-SO-000048
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-SO-000048

end
