# frozen_string_literal: true

module Prosopite
  DEFAULT_ALLOW_LIST = [
    %r{active_record/relation.rb.*preload_associations},
    "active_record/validations/uniqueness"
  ].freeze

  class NPlusOneQueriesError < StandardError
  end
  class << self
    attr_writer :raise,
                :stderr_logger,
                :rails_logger,
                :prosopite_logger,
                :custom_logger,
                :ignore_pauses,
                :backtrace_cleaner,
                :enabled

    attr_accessor :ignore_queries, :min_n_queries

    def backtrace_cleaner
      @backtrace_cleaner ||= Rails.backtrace_cleaner
    end

    def enabled?
      @enabled = true if @enabled.nil?

      @enabled
    end

    def disabled?
      !enabled?
    end

    def allow_stack_paths
      tc[:allow_stack_paths] || []
    end

    def allow_stack_paths=(paths)
      tc[:allow_stack_paths] = paths
    end

    def scan
      tc[:prosopite_scan] ||= false
      return block_given? ? yield : nil if scan? || disabled?

      subscribe

      tc[:prosopite_query_counter] = Hash.new(0)
      tc[:prosopite_query_holder] = Hash.new { |h, k| h[k] = [] }
      tc[:prosopite_query_caller] = {}

      @ignore_pauses ||= false
      @min_n_queries ||= 2

      tc[:prosopite_scan] = true

      return unless block_given?

      begin
        block_result = yield
        finish
        block_result
      ensure
        tc[:prosopite_scan] = false
      end
    end

    def tc
      Thread.current
    end

    def pause
      return block_given? ? yield : nil if @ignore_pauses

      if block_given?
        begin
          previous = tc[:prosopite_scan]
          tc[:prosopite_scan] = false
          yield
        ensure
          tc[:prosopite_scan] = previous
        end
      else
        tc[:prosopite_scan] = false
      end
    end

    def resume
      tc[:prosopite_scan] = true
    end

    def scan?
      !!(
        tc[:prosopite_scan] && tc[:prosopite_query_counter] &&
          tc[:prosopite_query_holder] && tc[:prosopite_query_caller]
      )
    end

    def finish
      return unless scan?

      tc[:prosopite_scan] = false

      create_notifications
      send_notifications if tc[:prosopite_notifications].present?

      tc[:prosopite_query_counter] = nil
      tc[:prosopite_query_holder] = nil
      tc[:prosopite_query_caller] = nil
    end

    def create_notifications
      tc[:prosopite_notifications] = {}

      tc[:prosopite_query_counter].each do |location_key, count|
        next unless count >= @min_n_queries

        fingerprints =
          tc[:prosopite_query_holder][location_key].group_by do |q|
            begin
              fingerprint(q)
            rescue StandardError
              raise q
            end
          end

        queries = fingerprints.values.select { |q| q.size >= @min_n_queries }

        next unless queries.any?

        location = tc[:prosopite_query_caller][location_key]
        allow_list = (allow_stack_paths + DEFAULT_ALLOW_LIST)
        is_allowed = location.any? { |f| allow_list.any? { |s| f.match?(s) } }

        queries.each do |q|
          tc[:prosopite_notifications][q] = location
        end unless is_allowed
      end
    end

    def fingerprint(query)
      case ActiveRecord::Base.connection
      when ActiveRecord::ConnectionAdapters::SQLite3Adapter
        begin
          require "sql_fingerprint"
        rescue LoadError => e
          msg =
            "Could not load the 'sql_fingerprint' gem. Add `gem 'sql_fingerprint'` to your Gemfile"
          raise LoadError, msg, e.backtrace
        end
        SqlFingerprint.calculate(query)
      when ActiveRecord::ConnectionAdapters::AbstractMysqlAdapter
        mysql_fingerprint(query)
      else
        begin
          require "pg_query"
        rescue LoadError => e
          msg =
            "Could not load the 'pg_query' gem. Add `gem 'pg_query'` to your Gemfile"
          raise LoadError, msg, e.backtrace
        end
        PgQuery.fingerprint(query)
      end
    end

    # Many thanks to https://github.com/genkami/fluent-plugin-query-fingerprint/
    def mysql_fingerprint(query)
      query = query.dup

      return "mysqldump" if query.start_with?("SELECT /*!40001 SQL_NO_CACHE */ * FROM `")

      return "percona-toolkit" if %r{\*\w+\.\w+:[0-9]/[0-9]\*/}.match?(query)
      if (match = /\A\s*(call\s+\S+)\(/i.match(query))
        return match.captures.first.downcase!
      end

      if (
           match =
             /\A((?:INSERT|REPLACE)(?: IGNORE)?\s+INTO.+?VALUES\s*\(.*?\))\s*,\s*\(/im.match(
               query
             )
         )
        query = match.captures.first
      end

      query.gsub!(%r{/\*[^!].*?\*/}m, "")
      query.gsub!(/(?:--|#)[^\r\n]*(?=[\r\n]|\Z)/, "")
      return query if query.gsub!(/\Ause \S+\Z/i, "use ?")

      query.gsub!(/\\["']/, "")
      query.gsub!(/".*?"/m, "?")
      query.gsub!(/'.*?'/m, "?")
      query.gsub!(/\btrue\b|\bfalse\b/i, "?")
      query.gsub!(/[0-9+-][0-9a-f.x+-]*/, "?")
      query.gsub!(/[xb.+-]\?/, "?")
      query.strip!
      query.gsub!(/[ \n\t\r\f]+/, " ")
      query.downcase!
      query.gsub!(/\bnull\b/i, "?")
      query.gsub!(/\b(in|values?)(?:[\s,]*\([\s?,]*\))+/, '\\1(?+)')
      query.gsub!(
        /(?<!\w)field\s*\(\s*(\S+)\s*,\s*(\?+)(?:\s*,\s*\?+)*\)/,
        'field(\1, \2+)'
      )
      query.gsub!(
        /\b(select\s.*?)(?:(\sunion(?:\sall)?)\s\1)+/,
        '\\1 /*repeat\\2*/'
      )
      query.gsub!(/\blimit \?(?:, ?\?| offset \?)/, "limit ?")
      query.gsub!(/\G(.+?)\s+asc/, '\\1') if /\border by/.match?(query)

      query
    end

    def send_notifications
      @custom_logger ||= nil
      @rails_logger ||= false
      @stderr_logger ||= false
      @prosopite_logger ||= false
      @raise ||= false

      notifications_str = +""

      tc[:prosopite_notifications].each do |queries, location|
        notifications_str << "N+1 queries detected:\n"

        queries.each { |q| notifications_str << "  #{q}\n" }

        notifications_str << "Call stack:\n"
        location = backtrace_cleaner.clean(location)
        location.each { |f| notifications_str << "  #{f}\n" }

        notifications_str << "\n"
      end

      @custom_logger&.warn(notifications_str)

      Rails.logger.warn(red(notifications_str)) if @rails_logger
      warn(red(notifications_str)) if @stderr_logger

      if @prosopite_logger
        File.open(File.join(Rails.root, "log", "prosopite.log"), "a") do |f|
          f.puts(notifications_str)
        end
      end

      raise NPlusOneQueriesError, notifications_str if @raise
    end

    def red(str)
      str.split("\n").map { |line| "\e[91m#{line}\e[0m" }.join("\n")
    end

    def ignore_query?(sql)
      @ignore_queries ||= []
      @ignore_queries.any? { |q| q === sql }
    end

    def subscribe
      @subscribed ||= false
      return if @subscribed

      ActiveSupport::Notifications.subscribe "sql.active_record" do |_, _, _, _, data|
        sql = data[:sql]
        name = data[:name]

        if scan? && name != "SCHEMA" && sql.include?("SELECT") &&
             data[:cached].nil? && !ignore_query?(sql)
          query_caller = caller
          location_key = Digest::SHA256.hexdigest(query_caller.join)

          tc[:prosopite_query_counter][location_key] += 1
          tc[:prosopite_query_holder][location_key] << sql

          tc[:prosopite_query_caller][location_key] = query_caller.dup if tc[
            :prosopite_query_counter
          ][
            location_key
          ] > 1
        end
      end

      @subscribed = true
    end
  end
end
