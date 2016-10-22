# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2013-07-25
# description: Microsoft Windows Server 2012 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.letterkenny.FSO.mbx.stig-customer-support-mailbox@mail.mil.
# impacts

title 'WN12-PK-000003 - The DoD Interoperability Root CA to DoD Root CA 2 cross-certificate must be installed into the Untrusted Certificates Store.'

control 'WN12-PK-000003' do
  impact 0.5
  title 'The DoD Interoperability Root CA to DoD Root CA 2 cross-certificate must be installed into the Untrusted Certificates Store.'
  desc '
To ensure users do not experience denial of service when performing certificate-based authentication to DoD websites due to the system chaining to a root other than DoD Root CA 2, the DoD Interoperability Root CA to DoD Root CA 2 cross-certificate must be installed in the Untrusted Certificate Store.
'
  tag 'stig','WN12-PK-000003'
  tag severity: 'medium'
  tag checkid: 'C-WN12-PK-000003_chk'
  tag fixid: 'F-WN12-PK-000003_fix'
  tag version: 'WN12-PK-000003'
  tag ruleid: 'WN12-PK-000003_rule'
  tag fixtext: '
Install the DoD Interoperability Root CA to DoD Root CA 2 cross-certificate.  Administrators should run the Federal Bridge Certification Authority (FBCA) Cross-Certificate Removal Tool once as an administrator and once as the current user.  The FBCA Cross-Certificate Remover tool and user guide is available on IASE at http://iase.disa.mil/pki-pke/function_pages/tools.html.
'
  tag checktext: '
Verify the DoD Root CA 2 certificate issued by DoD Interoperability Root CA 1 is installed as an Untrusted Certificate using the Certificates MMC snap-in:
Run "MMC".
Select "File", "Add/Remove Snap-in".
Select "Certificates", click "Add".
Select "Computer account", click "Next".
Select "Local computer: (the computer this console is running on)", click "Finish".
Click "OK".
Expand "Certificates" and navigate to "Untrusted Certificates\Certificates".
Search in the center pane for "DoD Root CA 2" under "Issued To" with "DoD Interoperability Root CA 1" as "Issued By".

If there is no entry for "DoD Root CA 2", this is a finding.

Select "DoD Root CA 2".
Right click and select "Open".
Select the "Details" Tab.
Scroll to the bottom and select "Thumbprint Algorithm".
Verify the Value is "sha1".

If the value for "Thumbprint Algorithm" is not "sha1", this is a finding.

Next select "Thumbprint".

If the value for the "Thumbprint" field is not
"b1:10:5c:d1:0f:c3:70:f5:6b:89:dd:1d:49:f6:d8:30:df:35:f2:de", this is a finding.
'

# START_DESCRIBE WN12-PK-000003
  # describe file('/etc') do
  #   it { should be_directory }
  # end
# END_DESCRIBE WN12-PK-000003

end
