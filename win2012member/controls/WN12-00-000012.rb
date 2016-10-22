# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-00-000012 - Shared user accounts must not be permitted on the system.'

control 'WN12-00-000012' do
  impact 0.5
  title 'Shared user accounts must not be permitted on the system.'
  desc '
Shared accounts (accounts where two or more people log in with the same user identification) do not provide adequate identification and authentication.  There is no way to provide for nonrepudiation or individual accountability for system access and resource usage.  Documentation must include a list of personnel that have access to each shared account.
'
  tag 'stig','WN12-00-000012'
  tag severity: 'medium'
  tag checkid: 'C-WN12-00-000012_chk'
  tag fixid: 'F-WN12-00-000012_fix'
  tag version: 'WN12-00-000012'
  tag ruleid: 'WN12-00-000012_rule'
  tag fixtext: '
Create or update shared account documentation that minimally contains the name of the shared accounts, the systems on which the accounts exist, and the individuals who have access to the accounts.   Remove any shared accounts that do not meet the requirements.
'
  tag checktext: '
Determine whether any shared accounts exist.  If no shared accounts exist, this is NA.

Any shared account must be documented with the IAO.  Documentation must include the reason for the account, who has access to this account, and how the risk of using a shared account (which provides no individual identification and accountability) is mitigated.    If such documentation does not exist, or is not current, this is a finding.
  
Note: As an example, a shared account may be permitted for a help desk or a site security personnel machine, if that machine is stand-alone and has no access to the network.
'

# START_DESCRIBE WN12-00-000012
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-00-000012

end
