# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000003 - The antivirus program signature files must be kept updated.'

control 'WN12-GE-000003' do
  impact 1.0
  title 'The antivirus program signature files must be kept updated.'
  desc '
Virus scan programs are a primary line of defense against the introduction of viruses and malicious code that can destroy data and even render a computer inoperable.  Utilizing the virus scan program provides the ability to detect malicious code before extensive damage occurs.  Updated virus scan data files help protect a system, as new malware is identified by the software vendors on a regular basis.
'
  tag 'stig','WN12-GE-000003'
  tag severity: 'high'
  tag checkid: 'C-WN12-GE-000003_chk'
  tag fixid: 'F-WN12-GE-000003_fix'
  tag version: 'WN12-GE-000003'
  tag ruleid: 'WN12-GE-000003_rule'
  tag fixtext: '
Configure the antivirus program to update the signature file at least every 7 days.  More frequent (daily) updates are recommended.
'
  tag checktext: '
Verify the signature file for the virus scan program is up to date.

If the antivirus program signature file is not dated within the past 7 days, this is a finding.

The version numbers and the date of the signature file can generally be checked by starting the antivirus program. The information may appear in the antivirus window or be available in the Help > About window. The location varies from product to product.

If V-19910 from an antivirus STIG has been applied to the system, this is NA.
'

# START_DESCRIBE WN12-GE-000003
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000003

end
