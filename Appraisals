case(RUBY_VERSION)
  when '2.3.3', '2.5.3' then
    appraise "ruby-#{RUBY_VERSION}_rails521" do
      gem 'rails',    '5.2.1'
    end
  else
    raise "Unsupported Ruby version #{RUBY_VERSION}"
end
