# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-00-000006 - Policy must require that system administrators (SAs) be trained for the operating systems used by systems under their control.'

control 'WN12-00-000006' do
  impact 0.5
  title 'Policy must require that system administrators (SAs) be trained for the operating systems used by systems under their control.'
  desc '
If SAs are assigned to systems running operating systems for which they have no training, these systems are at additional risk of unintentional misconfiguration that may result in vulnerabilities or decreased availability of the system.
'
  tag 'stig','WN12-00-000006'
  tag severity: 'medium'
  tag checkid: 'C-WN12-00-000006_chk'
  tag fixid: 'F-WN12-00-000006_fix'
  tag version: 'WN12-00-000006'
  tag ruleid: 'WN12-00-000006_rule'
  tag fixtext: '
Establish site policy that requires SAs be trained for all operating systems running on systems under their control.
'
  tag checktext: '
Review the list of SAs assigned to each system and compare this information to SA training records.  If SAs are assigned to systems running operating systems for which there is no record of training, this is a finding.
'

# START_DESCRIBE WN12-00-000006
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-00-000006

end
