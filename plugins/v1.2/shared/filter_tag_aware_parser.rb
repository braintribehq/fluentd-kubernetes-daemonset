#
# Fluentd
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#

require 'fluent/time'
require 'fluent/config/error'
require 'fluent/plugin/filter'
require 'fluent/plugin_helper/parser'
require 'fluent/plugin_helper/compat_parameters'

module Fluent::Plugin
  class TagAwareParserFilter < Filter
    Fluent::Plugin.register_filter('tag_aware_parser', self)

    helpers :parser, :record_accessor, :compat_parameters

    desc 'Specify field name in the record to parse.'
    config_param :key_name, :string
    desc 'Parse only records with this kubernetes label set.'
    config_param :kubernetes_label, :string, default: 'jsonlog'
    desc 'Reparse records with this kubernetes label set.'
    config_param :reparse_initiative_log, :string, default: 'initiative'
    desc 'Reparse records with this kubernetes label set. Uses format information from label'
    config_param :fluentd_format, :string, default: 'fluentd-format'
    desc 'Keep original key-value pair in parsed result.'
    config_param :reserve_data, :bool, default: false
    desc 'Keep original event time in parsed result.'
    config_param :reserve_time, :bool, default: false
    desc 'Remove "key_name" field from the record when parsing is succeeded'
    config_param :remove_key_name_field, :bool, default: false
    desc 'Store parsed values with specified key name prefix.'
    config_param :inject_key_prefix, :string, default: nil
    desc 'If true, invalid string is replaced with safe characters and re-parse it.'
    config_param :replace_invalid_sequence, :bool, default: false
    desc 'Store parsed values as a hash value in a field.'
    config_param :hash_value_field, :string, default: nil
    desc 'Emit invalid record to @ERROR label'
    config_param :emit_invalid_record_to_error, :bool, default: true

    attr_reader :parser

    def configure(conf)
      compat_parameters_convert(conf, :parser)

      super

      @accessor = record_accessor_create(@key_name)
      @parser = parser_create
      puts "ParserType: #{@parser}"
    end

    FAILED_RESULT = [nil, nil].freeze # reduce allocation cost
    REPLACE_CHAR = '?'.freeze

    def filter_with_time(tag, time, record)
      parse_initiative_log = record['kubernetes']['labels'][@reparse_initiative_log]
      fluentd_format = record['kubernetes']['labels'][@fluentd_format]
      json_log = record['kubernetes']['labels'][@kubernetes_label]
      unless  json_log || parse_initiative_log || fluentd_format
        return time, record
      end

      raw_value = @accessor.call(record)
      if raw_value.nil?
        if @emit_invalid_record_to_error
          router.emit_error_event(tag, time, record, ArgumentError.new("#{@key_name} does not exist"))
        end
        if @reserve_data
          return time, handle_parsed(tag, record, time, {})
        else
          return FAILED_RESULT
        end
      end

      if json_log
        #puts "fluentd_format: #{fluentd_format}"
        #puts "raw_value: #{raw_value}"
      end

      # handle custom logs
      if fluentd_format && !json_log
        case fluentd_format
        when 'traefik'
          # time="2018-09-20T09:30:12Z" level=debug msg="vulcand/oxy/forward/websocket: completed ServeHttp on request" Request="{\"Method\":\"GET\"}"
          # parse the "Request" field so that it's JSON
          ts = raw_value[/time="([^"]+)"/, 1]
          severity = raw_value[/level=([^ ]+)/, 1]
          message = raw_value[/msg="([^"]+)"/, 1]
          request = raw_value[/Request="(.+)" (ForwardURL)?/, 1]
          forward_url = raw_value[/ForwardURL="([^"]+)"/, 1]
          record['severity'] = severity
          record['message'] = message
          record['time'] = ts
          record['forward_url'] = forward_url
          if request
            raw_value = request.delete '\\'
          else
            return time, record
          end
        else
          return time, record
        end
      end

      # handle TF logs
      # 2018-08-31 08:23:32.310 SEVERE ladida
      if parse_initiative_log && !json_log
        #ts = raw_value[/(\d{4}-\d{2}-\d{2} [^\s]+)/, 1]
        severity = raw_value[/\d{4}-\d{2}-\d{2} [^\s]+ ([^\s]+)/, 1]
        message = raw_value[/\d{4}-\d{2}-\d{2} [^\s]+ [^\s]+ (.*)/, 1]
        record['severity'] = severity
        record['message'] = message
        return time, record
      end

      begin
        @parser.parse(raw_value) do |t, values|
          if values
            t = if @reserve_time
                  time
                else
                  t.nil? ? time : t
                end
            @accessor.delete(record) if @remove_key_name_field
            r = handle_parsed(tag, record, t, values, fluentd_format)
            #puts "Final record: #{r}"
            return t, r
          else
            if @emit_invalid_record_to_error
              router.emit_error_event(tag, time, record, Fluent::Plugin::Parser::ParserError.new("pattern not match with data '#{raw_value}'"))
            end
            if @reserve_data
              t = time
              r = handle_parsed(tag, record, time, {})
              return t, r
            else
              return FAILED_RESULT
            end
          end
        end
      rescue Fluent::Plugin::Parser::ParserError => e
        if @emit_invalid_record_to_error
          raise e
        else
          return FAILED_RESULT
        end
      rescue ArgumentError => e
        raise unless @replace_invalid_sequence
        raise unless e.message.index("invalid byte sequence in") == 0

        raw_value = raw_value.scrub(REPLACE_CHAR)
        retry
      rescue => e
        if @emit_invalid_record_to_error
          raise Fluent::Plugin::Parser::ParserError, "parse failed #{e.message}"
        else
          return FAILED_RESULT
        end
      end
    end

    private

    def handle_parsed(tag, record, t, values, custom_hash_value_field = nil)
      if values && @inject_key_prefix
        values = Hash[values.map {|k, v| [@inject_key_prefix + k, v]}]
      end
      if !custom_hash_value_field.nil?
        puts "Values go to #{custom_hash_value_field}: #{values}"
        r = {custom_hash_value_field => values}
      else
        r = @hash_value_field ? {@hash_value_field => values} : values
      end
      if @reserve_data
        r = r ? record.merge(r) : record
      end
      r
    end
  end
end
