# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-GE-000025 - The system must query the certification authority to determine whether a public key certificate has been revoked before accepting the certificate for authentication purposes.'

control 'WN12-GE-000025' do
  impact 0.5
  title 'The system must query the certification authority to determine whether a public key certificate has been revoked before accepting the certificate for authentication purposes.'
  desc '
Failure to verify a certificate\'s revocation status can result in the system accepting a revoked, and therefore unauthorized, certificate.  This could result in the installation of unauthorized software or a connection for rogue networks, depending on the use for which the certificate is intended.   Querying for certificate revocation mitigates the risk that the system will accept an unauthorized certificate.
'
  tag 'stig','WN12-GE-000025'
  tag severity: 'medium'
  tag checkid: 'C-WN12-GE-000025_chk'
  tag fixid: 'F-WN12-GE-000025_fix'
  tag version: 'WN12-GE-000025'
  tag ruleid: 'WN12-GE-000025_rule'
  tag fixtext: '
Install software that  provides certificate validation and revocation checking.
'
  tag checktext: '
Verify the system has software installed and running that provides certificate validation and revocation checking.  If it does not, this is a finding.
'

# START_DESCRIBE WN12-GE-000025
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-GE-000025

end
