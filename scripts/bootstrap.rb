#!/opt/puppetlabs/puppet/bin/ruby
require 'r10k/action/deploy/environment'
require 'r10k/action/runner'
require 'puppet'
require 'hiera'
require 'facter'
require 'puppetclassify'

@hkg_com_group = {
  "pe_repo" => {"master" => "lb.hkg.puppet.vm"},
  "role::com" => {}
}

@sin_com_group = {
  "pe_repo" => {"master" => "lb.sin.puppet.vm"},
  "role::com" => {}
}

@kl0_com_group = {
  "pe_repo" => {"master" => "lb.kl0.puppet.vm"},
  "role::com" => {}
}

@kl1_com_group = {
  "pe_repo" => {"master" => "lb.kl1.puppet.vm"},
  "role::com" => {}
}

@amq_hub_group = {
  "puppet_enterprise::profile::amq::hub" => {}
}

@hkg_mco_group = {
  "puppet_enterprise::profile::mcollective::agent" => {"activemq_brokers" => ["lb.hkg.puppet.vm"]}
}

@sin_mco_group = {
  "puppet_enterprise::profile::mcollective::agent" => {"activemq_brokers" => ["lb.sin.puppet.vm"]}
}

@kl0_mco_group = {
  "puppet_enterprise::profile::mcollective::agent" => {"activemq_brokers" => ["lb.kl0.puppet.vm"]}
}

@kl1_mco_group = {
  "puppet_enterprise::profile::mcollective::agent" => {"activemq_brokers" => ["lb.kl1.puppet.vm"]}
}

@lb_group = {
  "role::lb" => {}
}

@hiera_config = <<-EOS
---
:backends:
  - yaml
:hierarchy:
  - "%{::trusted.certname}"
  - common

:yaml:
  :datadir: /etc/puppetlabs/code/environments/%{environment}/hieradata
EOS

# Have puppet parse its config so we can call its settings
Puppet.initialize_settings

# Monkey patch some token support in
class PuppetHttps
  def get_with_token(url)
    url = URI.parse(url)
    accept = 'application/json'
    token = File.read('/root/.puppetlabs/token')

    req = Net::HTTP::Get.new("#{url.path}?#{url.query}", {"Accept" => accept, "X-Authentication" => token})
    res = make_ssl_request(url, req)
    res
  end

  def post_with_token(url, request_body=nil)
    url = URI.parse(url)
    token = File.read('/root/.puppetlabs/token')

    request = Net::HTTP::Post.new(url.request_uri, {"X-Authentication" => token})
    request.content_type = 'application/json'

    unless request_body.nil?
      request.body = request_body
    end

    res = make_ssl_request(url, request)
    res
  end
end

def fix_hiera(hiera_content)
  open('/etc/puppetlabs/puppet/hiera.yaml','w') do |f|
    f.puts hiera_content
  end
end

# Create classifier instance var
# Uses the local hostcertificate for auth ( assume we are
# running from master in whitelist entry of classifier ).
def load_classifier()
  auth_info = {
    'ca_certificate_path' => Puppet[:localcacert],
    'certificate_path'    => Puppet[:hostcert],
    'private_key_path'    => Puppet[:hostprivkey],
  }
  unless @classifier
    load_classifier_config
    @classifier = PuppetClassify.new(@classifier_url, auth_info)
    @classifier.update_classes.update
  end
end

# Read classifier.yaml for split installation compatibility
def load_classifier_config
  configfile = File.join Puppet.settings[:confdir], 'classifier.yaml'
  if File.exist?(configfile)
    classifier_yaml = YAML.load_file(configfile)
    @classifier_url = "https://#{classifier_yaml['server']}:#{classifier_yaml['port']}/classifier-api"
  else
    Puppet.debug "Config file #{configfile} not found"
    puts "no config file! - wanted #{configfile}"
    #exit 2
  end
end

def update_master(node_group, classes, rules)
  cputs "Updating #{node_group} Node Group"
  load_classifier
  @classifier.update_classes.update
  groups = @classifier.groups

  master_group = groups.get_groups.select { |group| group['name'] == node_group}

  raise "The #{node_group} group missing!" if master_group.empty?

  group_hash = master_group.first.merge({"classes" => classes,"rule" => rules})
  groups.update_group(group_hash)
end

def create_group(group_name,group_uuid,classes = {},rule_term,parent_group)
  load_classifier
  @classifier.update_classes.update
  groups = @classifier.groups
  current_group = groups.get_groups.select { |group| group['name'] == group_name}
  if current_group.empty?
    cputs "Creating #{group_name} group in classifier"
    groups.create_group({
      'name'    => group_name,
      'id'      => group_uuid,
      'classes' => classes,
      'parent'  => groups.get_group_id("#{parent_group}"),
      'rule'    => rule_term
    })
  else
    cputs "NODE GROUP #{group_name} ALREADY EXISTS!!! Skipping"
  end
end

def load_api_config
  master = Puppet.settings[:server]
  @master = master
  if master
    @rbac_url = "https://#{master}:4433/rbac-api"
    @cm_url   = "https://#{master}:8170/code-manager"
    @fs_url   = "https://#{master}:8140/file-sync"
    auth_info = {
      'ca_certificate_path' => Puppet[:localcacert],
      'certificate_path'    => Puppet[:hostcert],
      'private_key_path'    => Puppet[:hostprivkey],
      'read_timeout'        => 600
    }
    unless @api_setup
      @api_setup = PuppetHttps.new(auth_info)
    end
  else
    cputs "No master!"
  end
end

def new_user(user, token_dir)
  cputs "Creating new user #{user['login']}"
  load_api_config
  output = @api_setup.post("#{@rbac_url}/v1/users", user.to_json)
  if output.code.to_i < 400
    reset_user_password(output['location'].split('/').last, user['login'], token_dir)
  elsif output.code.to_i == 409
    puts "User exists"
    #retrieve the ID for the user here and reset password as per normal
  else
    raise Puppet::Error, "Failed to create new user: #{output.code} #{output.body}"
  end
end

def reset_user_password(user_id, user_login, token_dir)
  cputs "Reseting password for #{user_login}"
  load_api_config
  reset_token = @api_setup.post("#{@rbac_url}/v1/users/#{user_id}/password/reset")
  if reset_token.code.to_i < 400
    # yes I know this is not good programming practise, but this is me giving a shit right now.......
    password_reset = @api_setup.post("#{@rbac_url}/v1/auth/reset", { 'token' => reset_token.body, 'password' => 'モンスタートラック'}.to_json)
    if password_reset.code.to_i <= 400
      token = new_token({'login' => user_login, 'password' => 'モンスタートラック', 'lifetime' => '99d'}, token_dir)
    else
      raise Puppet::Error, "Failed to reset password: #{password_reset.code} #{password_reset.body}"
    end
  else
    raise Puppet::Error, "Failed to reset password: #{reset_token.code} #{reset_token.body}"
  end
end

def new_token(login, token_dir = nil)
  cputs "Creating token for #{login['login']}"
  load_api_config
  # https://tickets.puppetlabs.com/browse/PE-13331 issue
  output = @api_setup.post("#{@rbac_url}/v1/auth/token", login.to_json)
  if output.code.to_i <= 400
    if token_dir
      Dir.mkdir(token_dir) unless File.exists?(token_dir)
      f = open("#{token_dir}/token", 'w')
      f.write(JSON.parse(output.body)['token'])
      f.close
    end
  else
    raise Puppet::Error, "Failed to create new user: #{output.code} #{output.body}"
  end
end

def deploy_code
  cputs "Deploying code"
  load_api_config
  response = JSON.parse(@api_setup.post_with_token("#{@cm_url}/v1/deploys",{"deploy-all" => true, "wait" => true}.to_json).body)
  response.each do |x|
    if x['status'] != 'complete'
      raise Puppet::Error, "Code deployment failed, #{response.code} #{response.body}"
    end
  end
end

def commit_code
  cputs "Commiting code"
  load_api_config
  response = JSON.parse(@api_setup.post_with_token("#{@fs_url}/v1/commit",{"commit-all" => true}.to_json).body)
  if response['puppet-code']['status'] != 'ok'
    raise Puppet::Error, "Code deployment failed, #{response['puppet-code']['status']}"
  end
end

def test_class(class_name)
  load_classifier
  class_found = false
  while class_found == false do
    @classifier.update_classes.update
    response = JSON.parse(@api_setup.get_with_token(URI.escape("#{@classifier_url}/v1/environments/production/classes/#{class_name}")).body)
    if response['name'] == class_name
      class_found = true
      cputs "Found #{class_name} in NC registry"
    else
      cputs "#{class_name} not in NC registry as yet"
      commit_code
      sleep(30)
    end
  end
end

def cputs(string)
  puts "\033[1m#{string}\033[0m"
end

fix_hiera(@hiera_config)
new_user({ 'login' => 'deployer','display_name' => 'deployer','email' => 'deployer@puppet.com','role_ids' => [1]},'/root/.puppetlabs')
deploy_code
commit_code
update_master("PE Master", {"pe_repo::platform::aix_61_power" => {},"pe_repo::platform::aix_71_power" => {}, "pe_repo::platform::el_7_x86_64" => {}},["or",["or",["=",["trusted","extensions","pp_role"],"kl1_com"],["=",["trusted","extensions","pp_role"],"kl0_com"],["=",["trusted","extensions","pp_role"],"sin_com"],["=",["trusted","extensions","pp_role"],"hkg_com"]],["=","name","master.puppet.vm"]])
update_master("PE ActiveMQ Broker", {"puppet_enterprise::profile::amq::broker" => {}}, ["or",["=",["trusted","extensions","pp_role"],"hkg_com"],["=",["trusted","extensions","pp_role"],"sin_com"],["=",["trusted","extensions","pp_role"],"kl0_com"],["=",["trusted","extensions","pp_role"],"kl1_com"]])
create_group("PE MoM",'937f05eb-8185-4517-a609-3e64d05191d0',{"role::mom" => {}},["or",["=","certname","master.puppet.vm"]],'All Nodes')
create_group("HKG PE Compiler",'937f05eb-8185-4517-a609-3e64d05191c0',@hkg_com_group,["or",["=",["trusted","extensions","pp_role"],"hkg_com"]],'PE Master')
create_group("SIN PE Compiler",'937f05eb-8185-4517-a609-3e64d05191c1',@sin_com_group,["or",["=",["trusted","extensions","pp_role"],"sin_com"]],'PE Master')
create_group("KL0 PE Compiler",'937f05eb-8185-4517-a609-3e64d05191c2',@kl0_com_group,["or",["=",["trusted","extensions","pp_role"],"kl0_com"]],'PE Master')
create_group("KL1 PE Compiler",'937f05eb-8185-4517-a609-3e64d05191c3',@kl1_com_group,["or",["=",["trusted","extensions","pp_role"],"kl1_com"]],'PE Master')
create_group("PE ActiveMQ Hub",'937f05eb-8185-4517-a609-3e64d05191c4',@amq_hub_group,["or", ["=", "name", "master.puppet.vm"]],'PE Infrastructure')
create_group("HKG PE MCollective",'937f05eb-8185-4517-a609-3e64d05191c5',@hkg_mco_group,["and",["=",["trusted","extensions","pp_datacenter"],"hkg"],["not",["=",["trusted","extensions","pp_role"],"hkg_com"]],["not",["=",["trusted","extensions","pp_role"],"hkg_lb"]]],'PE MCollective')
create_group("SIN PE MCollective",'937f05eb-8185-4517-a609-3e64d05191c6',@sin_mco_group,["and",["=",["trusted","extensions","pp_datacenter"],"sin"],["not",["=",["trusted","extensions","pp_role"],"son_com"]],["not",["=",["trusted","extensions","pp_role"],"sin_lb"]]],'PE MCollective')
create_group("KL0 PE MCollective",'937f05eb-8185-4517-a609-3e64d05191c7',@kl0_mco_group,["and",["=",["trusted","extensions","pp_datacenter"],"kl0"],["not",["=",["trusted","extensions","pp_role"],"kl0_com"]],["not",["=",["trusted","extensions","pp_role"],"kl0_lb"]]],'PE MCollective')
create_group("KL1 PE MCollective",'937f05eb-8185-4517-a609-3e64d05191c8',@kl1_mco_group,["and",["=",["trusted","extensions","pp_datacenter"],"kl1"],["not",["=",["trusted","extensions","pp_role"],"kl1_com"]],["not",["=",["trusted","extensions","pp_role"],"kl1_lb"]]],'PE MCollective')
create_group("LB","937f05eb-8185-4517-a609-3e64d05191c9",@lb_group,["or",["=",["trusted","extensions","pp_role"],"hkg_lb"],["=",["trusted","extensions","pp_role"],"sin_lb"],["=",["trusted","extensions","pp_role"],"kl0_lb"],["=",["trusted","extensions","pp_role"],"kl1_lb"]],"All Nodes")
