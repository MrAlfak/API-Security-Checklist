#!/usr/bin/env ruby
# frozen_string_literal: true

require 'yaml'
require 'set'

ROOT = File.expand_path('..', __dir__)
CHECKLIST_DIR = File.join(ROOT, 'checklist')
INDEX_PATH = File.join(CHECKLIST_DIR, 'controls.yaml')
REQUIRED = %w[id title_en title_fa severity applies_to requirement verification evidence references].freeze

errors = []

begin
  index = YAML.safe_load(File.read(INDEX_PATH), permitted_classes: [], aliases: false)
rescue StandardError => e
  warn "Failed to load #{INDEX_PATH}: #{e.message}"
  exit 1
end

allowed_severity = Set.new(index.fetch('allowed_severity', []))
allowed_scope = Set.new(index.fetch('allowed_scope', []))
files = index.fetch('control_files', [])

errors << 'control_files must not be empty' if files.empty?
errors << 'allowed_severity must not be empty' if allowed_severity.empty?
errors << 'allowed_scope must not be empty' if allowed_scope.empty?

ids = Set.new
control_count = 0

files.each do |relative|
  path = File.join(CHECKLIST_DIR, relative)
  unless File.file?(path)
    errors << "missing control file: #{relative}"
    next
  end

  begin
    doc = YAML.safe_load(File.read(path), permitted_classes: [], aliases: false)
  rescue StandardError => e
    errors << "#{relative}: invalid YAML: #{e.message}"
    next
  end

  controls = doc.is_a?(Hash) ? doc['controls'] : nil
  unless controls.is_a?(Array) && !controls.empty?
    errors << "#{relative}: controls must be a non-empty array"
    next
  end

  controls.each_with_index do |control, index_in_file|
    label = "#{relative}[#{index_in_file}]"
    unless control.is_a?(Hash)
      errors << "#{label}: control must be a mapping"
      next
    end

    REQUIRED.each do |field|
      value = control[field]
      empty = value.nil? || (value.respond_to?(:empty?) && value.empty?)
      errors << "#{label}: missing/empty #{field}" if empty
    end

    id = control['id']
    if id
      if ids.include?(id)
        errors << "#{label}: duplicate id #{id}"
      else
        ids << id
      end
      errors << "#{label}: invalid id format #{id}" unless id.match?(/\A[A-Z0-9]+(?:-[A-Z0-9]+)+\z/)
    end

    severity = control['severity']
    errors << "#{label}: invalid severity #{severity}" if severity && !allowed_severity.include?(severity)

    scopes = control['applies_to']
    if scopes.is_a?(Array)
      scopes.each do |scope|
        errors << "#{label}: invalid scope #{scope}" unless allowed_scope.include?(scope)
      end
    else
      errors << "#{label}: applies_to must be an array"
    end

    %w[verification evidence references].each do |field|
      value = control[field]
      errors << "#{label}: #{field} must be a non-empty array" unless value.is_a?(Array) && !value.empty?
    end

    control_count += 1
  end
end

if errors.any?
  warn "Control validation failed with #{errors.length} error(s):"
  errors.each { |error| warn "- #{error}" }
  exit 1
end

puts "Validated #{control_count} controls across #{files.length} files; all IDs are unique."
