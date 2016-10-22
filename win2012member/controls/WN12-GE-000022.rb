# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000022 - Servers must have a host-based Intrusion Detection System.'

control 'WN12-GE-000022' do
  impact 0.5
  title 'Servers must have a host-based Intrusion Detection System.'
  desc '
A properly configured host-based Intrusion Detection System provides another level of defense against unauthorized access to critical servers.  With proper configuration and logging enabled, such a system can stop and/or alert for many attempts to gain unauthorized access to resources.
'
  tag 'stig','WN12-GE-000022'
  tag severity: 'medium'
  tag checkid: 'C-WN12-GE-000022_chk'
  tag fixid: 'F-WN12-GE-000022_fix'
  tag version: 'WN12-GE-000022'
  tag ruleid: 'WN12-GE-000022_rule'
  tag fixtext: '
Install a host-based Intrusion Detection System on each server.
'
  tag checktext: '
Determine whether there is a host-based Intrusion Detection System on each server. 

If the HIPS component of HBSS is installed and active on the host and the Alerts of blocked activity are being logged and monitored, this will meet the requirement of this finding. 

A HID device is not required on a system that has the role as the Network Intrusion Device (NID). However, this exception needs to be documented with the site IAO.

Severity Override:  This finding can be downgraded to a CAT III, if there is an active JIDS or firewall protecting the network.
'

# START_DESCRIBE WN12-GE-000022
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000022

end
