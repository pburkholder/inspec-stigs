# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000001 - Systems must be maintained at a supported service pack level.'

control 'WN12-GE-000001' do
  impact 1.0
  title 'Systems must be maintained at a supported service pack level.'
  desc '
Systems at unsupported service packs or releases will not receive security updates for new vulnerabilities, which leaves them subject to exploitation.  Systems must be maintained at a service pack level supported by the vendor with new security updates.
'
  tag 'stig','WN12-GE-000001'
  tag severity: 'high'
  tag checkid: 'C-WN12-GE-000001_chk'
  tag fixid: 'F-WN12-GE-000001_fix'
  tag version: 'WN12-GE-000001'
  tag ruleid: 'WN12-GE-000001_rule'
  tag fixtext: '
Update the system to a supported release or service pack level.

Application of new service packs must be thoroughly tested before deploying in a production environment.
'
  tag checktext: '
Run "winver.exe". 

If the "About Windows" dialog box does not display 
"Microsoft Windows Server 
Version 6.2 (Build 9200)"
or greater, this is a finding. 
      
No preview versions will be used in a production environment. 

Unsupported Service Packs/Releases:
Windows 2012 - any release candidates or versions prior to the initial release.
'

# START_DESCRIBE WN12-GE-000001
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000001

end
