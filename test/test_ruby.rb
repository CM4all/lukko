#!/usr/bin/env ruby

require 'net/ssh'

Net::SSH.start(ARGV[1], ARGV[0], port:ARGV[2].to_i, keys:[ARGV[3]], verbose: Logger::DEBUG) do |ssh|
  output = ssh.exec!("echo hello")
  abort(output) if output != "hello\n"
end
