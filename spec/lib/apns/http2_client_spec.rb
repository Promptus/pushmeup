require 'spec_helper'

describe APNS::Http2Client do

  let(:auth_key) do
    "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPMhdb8bRyZsKcNGNmrH4rLQKW/uANUuRA88rpTSl4eMoAoGCCqGSM49
AwEHoUQDQgAE+YAdcIW1yhq5WfVeaZqK+b91DF6P+saXgIFazp1trgooRZ9EkOqr
tp851pHoPmPwGe7coEYZmtmNkoPNqNsshg==
-----END EC PRIVATE KEY-----"
  end
  let(:key_id) { "AAAAAAAAAA" }
  let(:team_id) { "BBBBBBBBBB" }
  let(:app_id) { "de.pushmeup.test" }
  let(:mode) { :development }

  let(:message) do
    { :alert => "Test" }
  end

  let(:client) { APNS::Http2Client.new(auth_key, key_id, team_id, mode) }

  it 'should raise if the openssl version is 0.x' do
    stub_const("OpenSSL::OPENSSL_VERSION", "OpenSSL 0.9.8zh 14 Jan 2016")
    expect { client }.to raise_error(RuntimeError)
  end

  it 'should raise if the openssl version is 1.0.0' do
    stub_const("OpenSSL::OPENSSL_VERSION", "OpenSSL 1.0.0b 14 Jan 2016")
    expect { client }.to raise_error(RuntimeError)
  end

  it 'should not be production mode' do
    expect(client).to_not be_production
  end

  describe 'mode production' do
    let(:mode) { :production }

    it 'should be production mode' do
      expect(client).to be_production
    end
  end
  

end
