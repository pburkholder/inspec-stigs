# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38454 - The system package management tool must verify ownership on all files and directories associated with packages.'

control 'V-38454' do
  impact 0.1
  title 'The system package management tool must verify ownership on all files and directories associated with packages.'
  desc '
Ownership of system binaries and configuration files that is incorrect could allow an unauthorized user to gain privileges that they should not have. The ownership set by the vendor should be maintained. Any deviations from this baseline should be investigated.
'
  tag 'stig','V-38454','long','rpm'
  tag severity: 'low'
  tag checkid: 'C-46010r1_chk'
  tag fixid: 'F-43400r1_fix'
  tag version: 'RHEL-06-000516'
  tag ruleid: 'SV-50254r1_rule'
  tag fixtext: '
The RPM package management system can restore ownership of package files and directories. The following command will update files and directories with ownership different from what is expected by the RPM database:

# rpm -qf [file or directory name]
# rpm --setugids [package]
'
  tag checktext: '
The following command will list which files on the system have ownership different from what is expected by the RPM database:

# rpm -Va | grep \'^.....U\'


If there is output, this is a finding.
'

# START_DESCRIBE V-38454
  describe command("rpm -Va | grep '^.....U'") do
    its('stdout') { should eq '' }
  end
# END_DESCRIBE V-38454

end
