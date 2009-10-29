require 'optparse'
require 'net/smtp'
require File.join(File.dirname(__FILE__), '..', 'smtp_tls') unless Net::SMTP.instance_methods.include?("enable_starttls_auto")
require 'rubygems'

##
# Hack in RSET

module Net # :nodoc:
class SMTP # :nodoc:

  unless instance_methods.include? 'reset' then
    ##
    # Resets the SMTP connection.

    def reset
      getok 'RSET'
    end
  end

end
end

##
# ActionMailer::ARSendmail delivers email from the email table to the
# SMTP server configured in your application's config/environment.rb.
# ar_sendmail does not work with sendmail delivery.
#
# ar_mailer can deliver to SMTP with TLS using smtp_tls.rb borrowed from Kyle
# Maxwell's action_mailer_optional_tls plugin.  Simply set the :tls option in
# ActionMailer::Base's smtp_settings to true to enable TLS.
#
# See ar_sendmail -h for the full list of supported options.
#
# The interesting options are:
# * --daemon
# * --mailq

module ActionMailer; end

class ActionMailer::ARSendmail

  ##
  # The version of ActionMailer::ARSendmail you are running.

  VERSION = '2.1.5'

  ##
  # Maximum number of times authentication will be consecutively retried

  MAX_AUTH_FAILURES = 2

  ##
  # Email delivery attempts per run

  attr_accessor :batch_size

  ##
  # Seconds to delay between runs

  attr_accessor :delay

  ##
  # Maximum age of emails in seconds before they are removed from the queue.

  attr_accessor :max_age

  ##
  # Be verbose

  attr_accessor :verbose
 

  ##
  # True if only one delivery attempt will be made per call to run

  attr_reader :once

  ##
  # Times authentication has failed

  attr_accessor :failed_auth_count

  @@pid_file = nil

  def self.remove_pid_file
    if @@pid_file
      require 'shell'
      sh = Shell.new
      sh.rm @@pid_file
    end
  end

  ##
  # Prints a list of unsent emails and the last delivery attempt, if any.
  #
  # If ActiveRecord::Timestamp is not being used the arrival time will not be
  # known.  See http://api.rubyonrails.org/classes/ActiveRecord/Timestamp.html
  # to learn how to enable ActiveRecord::Timestamp.

  def self.mailq
    emails = ActionMailer::Base.email_class.find :all

    if emails.empty? then
      puts "Mail queue is empty"
      return
    end

    total_size = 0

    puts "-Queue ID- --Size-- ----Arrival Time---- -Sender/Recipient-------"
    emails.each do |email|
      size = email.mail.length
      total_size += size

      create_timestamp = email.created_on rescue
                         email.created_at rescue
                         Time.at(email.created_date) rescue # for Robot Co-op
                         nil

      created = if create_timestamp.nil? then
                  '             Unknown'
                else
                  create_timestamp.strftime '%a %b %d %H:%M:%S'
                end

      puts "%10d %8d %s  %s" % [email.id, size, created, email.from]
      if email.last_send_attempt > 0 then
        puts "Last send attempt: #{Time.at email.last_send_attempt}"
      end
      puts "                                         #{email.to}"
      puts
    end

    puts "-- #{total_size/1024} Kbytes in #{emails.length} Requests."
  end

  ##
  # Processes command line options in +args+

  def self.process_args(args)
    name = File.basename $0

    options = {}
    options[:Chdir] = '.'
    options[:Daemon] = false
    options[:Delay] = 60
    options[:MaxAge] = 86400 * 7
    options[:Once] = false
    options[:RailsEnv] = ENV['RAILS_ENV']
    options[:Pidfile] = options[:Chdir] + '/log/ar_sendmail.pid'

    opts = OptionParser.new do |opts|
      opts.banner = "Usage: #{name} [options]"
      opts.separator ''

      opts.separator "#{name} scans the email table for new messages and sends them to the"
      opts.separator "website's configured SMTP host."
      opts.separator ''
      opts.separator "#{name} must be run from a Rails application's root."

      opts.separator ''
      opts.separator 'Sendmail options:'

      opts.on("-b", "--batch-size BATCH_SIZE",
              "Maximum number of emails to send per delay",
              "Default: Deliver all available emails", Integer) do |batch_size|
        options[:BatchSize] = batch_size
      end

      opts.on(      "--delay DELAY",
              "Delay between checks for new mail",
              "in the database",
              "Default: #{options[:Delay]}", Integer) do |delay|
        options[:Delay] = delay
      end

      opts.on(      "--max-age MAX_AGE",
              "Maxmimum age for an email. After this",
              "it will be removed from the queue.",
              "Set to 0 to disable queue cleanup.",
              "Default: #{options[:MaxAge]} seconds", Integer) do |max_age|
        options[:MaxAge] = max_age
      end

      opts.on("-o", "--once",
              "Only check for new mail and deliver once",
              "Default: #{options[:Once]}") do |once|
        options[:Once] = once
      end

      opts.on("-d", "--daemonize",
              "Run as a daemon process",
              "Default: #{options[:Daemon]}") do |daemon|
        options[:Daemon] = true
      end

      opts.on("-p", "--pidfile PIDFILE",
              "Set the pidfile location",
              "Default: #{options[:Chdir]}#{options[:Pidfile]}", String) do |pidfile|
        options[:Pidfile] = pidfile
      end

      opts.on(      "--mailq",
              "Display a list of emails waiting to be sent") do |mailq|
        options[:MailQ] = true
      end

      opts.separator ''
      opts.separator 'Setup Options:'

      opts.separator ''
      opts.separator 'Generic Options:'

      opts.on("-c", "--chdir PATH",
              "Use PATH for the application path",
              "Default: #{options[:Chdir]}") do |path|
        usage opts, "#{path} is not a directory" unless File.directory? path
        usage opts, "#{path} is not readable" unless File.readable? path
        options[:Chdir] = path
      end

      opts.on("-e", "--environment RAILS_ENV",
              "Set the RAILS_ENV constant",
              "Default: #{options[:RailsEnv]}") do |env|
        options[:RailsEnv] = env
      end

      opts.on("-v", "--[no-]verbose",
              "Be verbose",
              "Default: #{options[:Verbose]}") do |verbose|
        options[:Verbose] = verbose
      end

      opts.on("-h", "--help",
              "You're looking at it") do
        usage opts
      end

      opts.on("--version", "Version of ARMailer") do
        usage "ar_mailer #{VERSION} (adzap fork)"
      end

      opts.separator ''
    end

    opts.parse! args

    ENV['RAILS_ENV'] = options[:RailsEnv]

    Dir.chdir options[:Chdir] do
      begin
        require 'config/environment'
        require 'action_mailer/ar_mailer'
      rescue LoadError
        usage opts, <<-EOF
#{name} must be run from a Rails application's root to deliver email.
#{Dir.pwd} does not appear to be a Rails application root.
        EOF
      end
    end

    return options
  end

  ##
  # Processes +args+ and runs as appropriate

  def self.run(args = ARGV)
    options = process_args args

    if options.include? :MailQ then
      mailq
      exit
    end

    if options[:Daemon] then
      require 'webrick/server'
      @@pid_file = File.expand_path(options[:Pidfile], options[:Chdir])
      if File.exists? @@pid_file
        # check to see if process is actually running
        pid = ''
        File.open(@@pid_file, 'r') {|f| pid = f.read.chomp }
        if system("ps -p #{pid} | grep #{pid}") # returns true if process is running, o.w. false
          $stderr.puts "Warning: The pid file #{@@pid_file} exists and ar_sendmail is running. Shutting down."
          exit
        else
          # not running, so remove existing pid file and continue
          self.remove_pid_file
          $stderr.puts "ar_sendmail is not running. Removing existing pid file and starting up..."
        end
      end
      WEBrick::Daemon.start
      File.open(@@pid_file, 'w') {|f| f.write("#{Process.pid}\n")}
    end

    new(options).run

  rescue SystemExit
    raise
  rescue SignalException
    exit
  rescue Exception => e
    $stderr.puts "Unhandled exception #{e.message}(#{e.class}):"
    $stderr.puts "\t#{e.backtrace.join "\n\t"}"
    exit 1
  end

  ##
  # Prints a usage message to $stderr using +opts+ and exits

  def self.usage(opts, message = nil)
    if message then
      $stderr.puts message
      $stderr.puts
    end

    $stderr.puts opts
    exit 1
  end

  ##
  # Creates a new ARSendmail.
  #
  # Valid options are:
  # <tt>:BatchSize</tt>:: Maximum number of emails to send per delay
  # <tt>:Delay</tt>:: Delay between deliver attempts
  # <tt>:Once</tt>:: Only attempt to deliver emails once when run is called
  # <tt>:Verbose</tt>:: Be verbose.

  def initialize(options = {})
    options[:Delay] ||= 60
    options[:MaxAge] ||= 86400 * 7

    @batch_size = options[:BatchSize]
    @delay = options[:Delay]
    @once = options[:Once]
    @verbose = options[:Verbose]
    @max_age = options[:MaxAge]
    @smtp_settings = options[:smtp_settings]

    @failed_auth_count = 0
  end

  ##
  # Removes emails that have lived in the queue for too long.  If max_age is
  # set to 0, no emails will be removed.

  def cleanup
    return if @max_age == 0
    timeout = Time.now - @max_age
    conditions = ['last_send_attempt > 0 and created_on < ?', timeout]
    mail = ActionMailer::Base.email_class.destroy_all conditions

    log "expired #{mail.length} emails from the queue"
  end

  ##
  # Delivers +emails+ to ActionMailer's SMTP server and destroys them.

  def deliver(emails)
    settings = [
      smtp_settings[:domain],
      (smtp_settings[:user] || smtp_settings[:user_name]),
      smtp_settings[:password],
      smtp_settings[:authentication]
    ]
    
    smtp = Net::SMTP.new(smtp_settings[:address], smtp_settings[:port])
    if smtp.respond_to?(:enable_starttls_auto)
      smtp.enable_starttls_auto unless smtp_settings[:tls] == false
    else
      settings << smtp_settings[:tls]
    end

    smtp.start(*settings) do |session|
      @failed_auth_count = 0
      until emails.empty? do
        email = emails.shift
        begin
          res = session.send_message email.mail, email.from, email.to
          email.destroy
          log "sent email %011d from %s to %s: %p" %
                [email.id, email.from, email.to, res]
        rescue Net::SMTPFatalError => e
          log "5xx error sending email %d, removing from queue: %p(%s):\n\t%s" %
                [email.id, e.message, e.class, e.backtrace.join("\n\t")]
          email.destroy
          session.reset
        rescue Net::SMTPServerBusy => e
          log "server too busy, sleeping #{@delay} seconds"
          sleep delay
          return
        rescue Net::SMTPUnknownError, Net::SMTPSyntaxError, TimeoutError => e
          email.last_send_attempt = Time.now.to_i
          email.save rescue nil
          log "error sending email %d: %p(%s):\n\t%s" %
                [email.id, e.message, e.class, e.backtrace.join("\n\t")]
          session.reset
        end
      end
    end
  rescue Net::SMTPAuthenticationError => e
    @failed_auth_count += 1
    if @failed_auth_count >= MAX_AUTH_FAILURES then
      log "authentication error, giving up: #{e.message}"
      raise e
    else
      log "authentication error, retrying: #{e.message}"
    end
    sleep delay
  rescue Net::SMTPServerBusy, SystemCallError, OpenSSL::SSL::SSLError
    # ignore SMTPServerBusy/EPIPE/ECONNRESET from Net::SMTP.start's ensure
  end

  ##
  # Prepares ar_sendmail for exiting

  def do_exit
    log "caught signal, shutting down"
    self.class.remove_pid_file
    exit
  end

  ##
  # Returns emails in email_class that haven't had a delivery attempt in the
  # last 300 seconds.

  def find_emails
    options = { :conditions => ['last_send_attempt < ? and ready', Time.now.to_i - 300] }
    options[:limit] = batch_size unless batch_size.nil?
    mail = ActionMailer::Base.email_class.find :all, options

    log "found #{mail.length} emails to send"
    mail
  end

  ##
  # Installs signal handlers to gracefully exit.

  def install_signal_handlers
    trap 'TERM' do do_exit end
    trap 'INT'  do do_exit end
  end

  ##
  # Logs +message+ if verbose

  def log(message)
    $stderr.puts message if @verbose
    ActionMailer::Base.logger.info "ar_sendmail: #{message}"
  end

  ##
  # Scans for emails and delivers them every delay seconds.  Only returns if
  # once is true.

  def run
    install_signal_handlers

    loop do
      now = Time.now
      deliver_emails
      break if @once
      sleep @delay if now + @delay > Time.now
    end
  end

  def deliver_emails
    begin
      cleanup
      emails = find_emails
      deliver(emails) unless emails.empty?
    rescue ActiveRecord::Transactions::TransactionError
    end
  end
  
  ##
  # Proxy to ActionMailer::Base::smtp_settings.  See
  # http://api.rubyonrails.org/classes/ActionMailer/Base.html
  # for instructions on how to configure ActionMailer's SMTP server.
  #
  # Falls back to ::server_settings if ::smtp_settings doesn't exist for
  # backwards compatibility.

  def smtp_settings
    @smtp_settings ||= ActionMailer::Base.smtp_settings rescue ActionMailer::Base.server_settings
  end

  ##
  # Packs non-digested messages into digests, and send them
  # options: (see default values in first lines of code)
  #   :dump_path - dir in which to dump full digest message in case it needs to be truncated.
  #   :subj_prefix - specifies subject prefix that is already set to all the messages. If it's specified it's removed from subjects when combining them into digest's subject.
  #   :max_subj_size - maximum subject size of digest email  
  #   :mail_body_size_limit - maximum body size of digest email
  #   :smtp_settings - what smtp settings to use. Hash is expected described in http://api.rubyonrails.org/classes/ActionMailer/Base.html, +setting :tls to false will work. If omitted asks it from #smtp_settings method  
  def self.digest_error_emails(options = {})
    options.reverse_merge! :dump_path => 'log', :max_subj_size => 150, :mail_body_size_limit => 1.megabyte 
    
    subj_prefix = options[:subj_prefix] 
    max_subj_size = options[:max_subj_size]
    mail_body_size_limit = options[:mail_body_size_limit]

    email_class = ActionMailer::Base.email_class
    #Email.count(:group => :to) doesn't work because to is reserved word in MySQL
    counts = email_class.connection.select_rows("select `to`, count(*) AS count_all FROM `emails` where !ready GROUP BY `to`")
    counts.each do |to, count|
      if count.to_i == 1
        email_class.update_all(['ready = ?', true], ['`to` = ?', to])
        next
      end
      subjects = []
      mails = []
      from = nil
      email_class.transaction do
        emails = email_class.find(:all, :conditions => {:to => to, :ready => false}, :order => 'created_on')
        msg = nil
        email = nil
        last_date = nil
        emails.each do |email|
          msg = TMail::Mail.parse(email.mail)
          subject = msg.subject
          subject = subject[subj_prefix.length..-1] if subject.starts_with?(subj_prefix)
          subjects << subject
          mail = msg.header.select {|key, value| ['date', 'from', 'subject'].include?(key)}.
                  map {|key, value| '%s: %s' % [key.capitalize, value.to_s]}.join("\n")
          #some providers don't write Date header, e.g. ExceptionNotifier. but it's really welcome in digest items
          mail = "Date: #{email.created_on}\n#{mail}" unless msg.header['date']
          mail += "\n\n" + msg.body
          mails << mail
          from = msg.header['from'].to_s
          last_date = msg.date
          email.destroy
        end
        new = TMail::Mail.new
        new.to = to
        new.from = from
        subject = subj_prefix + subjects.uniq.join("; ")
        new.subject = subject.size > max_subj_size ? subject[0..max_subj_size] + '... (and more)' : subject
        new.mime_version = msg.mime_version
        new.content_type = "text/plain" #this code doesn't really support anything else
        new.charset = msg.charset
        new.date = last_date
        splitter = "\n" + '=' * 70 + "\n"
        body = splitter + mails.join(splitter)
        if body.size > mail_body_size_limit
          email_dump_path = options[:dump_path] + "/err.emails.#{Time.now.to_i}"
          File.open(email_dump_path, 'w') do |f|
            f.write(body)
          end
          old_size = body.size
          body = body[0..mail_body_size_limit] #yeah it will be bit more considering the header, but we don't care
          new_num = body.split(splitter).size
          body = ("WARNING: not all the messages made it into this digest - some are lost in truncation. " +
                  "Original number of messages - #{mails.size} (here only #{new_num}); original size - #{old_size} " +
                  "(here only #{body.size}). Full dump of original emails is placed in #{email_dump_path} @#{`hostname`.strip}.\n\n") + body
        else
          body = "This digest has #{mails.size} messages for you:\n\n" + body  
        end
        new.body = body
        email_class.create!(:from => email.from, :to => to, :mail => new.to_s, :ready => true)
      end
    end
    self.new(:smtp_settings => options[:smtp_settings]).deliver_emails
  end
end
