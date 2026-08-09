#!/usr/bin/env ruby
# frozen_string_literal: true

require 'yaml'
require 'set'

ROOT = File.expand_path('..', __dir__)
CHECKLIST_DIR = File.join(ROOT, 'checklist')
INDEX_PATH = File.join(CHECKLIST_DIR, 'controls.yaml')
REQUIRED = %w[
  id title_en title_fa severity applies_to
  requirement requirement_fa
  verification verification_fa
  evidence evidence_fa
  references
].freeze
ARRAY_FIELDS = %w[verification verification_fa evidence evidence_fa references].freeze
PERSIAN_PATTERN = /[\u0600-\u06FF]/.freeze

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

    ARRAY_FIELDS.each do |field|
      value = control[field]
      errors << "#{label}: #{field} must be a non-empty array" unless value.is_a?(Array) && !value.empty?
    end

    if control['verification'].is_a?(Array) && control['verification_fa'].is_a?(Array) &&
       control['verification'].length != control['verification_fa'].length
      errors << "#{label}: verification_fa item count must match verification"
    end

    if control['evidence'].is_a?(Array) && control['evidence_fa'].is_a?(Array) &&
       control['evidence'].length != control['evidence_fa'].length
      errors << "#{label}: evidence_fa item count must match evidence"
    end

    %w[title_fa requirement_fa].each do |field|
      value = control[field]
      if value.is_a?(String) && !value.match?(PERSIAN_PATTERN)
        errors << "#{label}: #{field} must contain Persian text"
      end
    end

    if control['verification_fa'].is_a?(Array) &&
       !control['verification_fa'].join(' ').match?(PERSIAN_PATTERN)
      errors << "#{label}: verification_fa must contain Persian text"
    end

    if control['evidence_fa'].is_a?(Array) &&
       !control['evidence_fa'].join(' ').match?(PERSIAN_PATTERN)
      errors << "#{label}: evidence_fa must contain Persian text"
    end

    control_count += 1
  end
end

if errors.any?
  warn "Control validation failed with #{errors.length} error(s):"
  errors.each { |error| warn "- #{error}" }
  exit 1
end

puts "Validated #{control_count} fully bilingual controls across #{files.length} files; all IDs are unique."
