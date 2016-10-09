# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38518 - All rsyslog-generated log files must be owned by root.'

control 'V-38518' do
  impact 0.5
  title 'All rsyslog-generated log files must be owned by root.'
  desc '
The log files generated by rsyslog contain valuable information regarding system configuration, user authentication, and other such information. Log files should be protected from unauthorized access.
'
  tag 'stig','V-38518'
  tag severity: 'medium'
  tag checkid: 'C-46075r2_chk'
  tag fixid: 'F-43465r1_fix'
  tag version: 'RHEL-06-000133'
  tag ruleid: 'SV-50319r2_rule'
  tag fixtext: '
The owner of all log files written by "rsyslog" should be root. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" typically all appear in "/var/log". For each log file [LOGFILE] referenced in "/etc/rsyslog.conf", run the following command to inspect the file\'s owner:

$ ls -l [LOGFILE]

If the owner is not "root", run the following command to correct this:

# chown root [LOGFILE]
'
  tag checktext: '
The owner of all log files written by "rsyslog" should be root. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" and typically all appear in "/var/log". To see the owner of a given log file, run the following command:

$ ls -l [LOGFILE]

Some log files referenced in /etc/rsyslog.conf may be created by other programs and may require exclusion from consideration.

If the owner is not root, this is a finding.
'

# START_DESCRIBE V-38518
  ["messages","secure","maillog","cron","spooler","boot.log"].each do |log|
    describe file("/var/log/#{log}") do
      its('owner') { should eq 'root' }
    end
  end
# END_DESCRIBE V-38518

end
