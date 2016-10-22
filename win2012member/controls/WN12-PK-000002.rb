# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-PK-000002 - The External CA root certificate must be installed into the Trusted Root Store.'

control 'WN12-PK-000002' do
  impact 0.5
  title 'The External CA root certificate must be installed into the Trusted Root Store.'
  desc '
To ensure secure websites protected with ECA server certificates are properly validated, the system must trust the ECA Root CA 2.  The ECA root certificate will ensure the trust chain is established for server certificates issued from the External CA.
'
  tag 'stig','WN12-PK-000002'
  tag severity: 'medium'
  tag checkid: 'C-WN12-PK-000002_chk'
  tag fixid: 'F-WN12-PK-000002_fix'
  tag version: 'WN12-PK-000002'
  tag ruleid: 'WN12-PK-000002_rule'
  tag fixtext: '
Install the ECA Root CA 2 certificate.  The InstallRoot tool is available on IASE at http://iase.disa.mil/pki-pke/function_pages/tools.html.
'
  tag checktext: '
Verify the ECA Root CA 2 certificate is installed as a Trusted Root Certification Authority using the Certificates MMC snap-in:
Run "MMC".
Select "File", "Add/Remove Snap-in".
Select "Certificates", click "Add".
Select "Computer account", click "Next".
Select "Local computer: (the computer this console is running on)", click "Finish".
Click "OK".
Expand "Certificates" and navigate to "Trusted Root Certification Authorities\Certificates".
Search for "ECA Root CA 2" under "Issued To" in the center pane.

If there is no entry for "ECA Root CA 2", this is a finding.

Select "ECA Root CA 2".
Right click and select "Open".
Select the "Details" Tab.
Scroll to the bottom and select "Thumbprint Algorithm".
Verify the Value is "sha1".

If the value for Thumbprint Algorithm is not "sha1", this is a finding.

Next select "Thumbprint".

If the value for the "Thumbprint" field is not
"c3:13:f9:19:a6:ed:4e:0e:84:51:af:a9:30:fb:41:9a:20:f1:81:e4", this is a finding.
'

# START_DESCRIBE WN12-PK-000002
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-PK-000002

end
