class PledgeTest < Picoruby::Test
  def setup
    Dir.mkdir(settings[:path])
  end

  def teardown
    Dir.rmdir(settings[:path])
    jail.remove
  end

  def test_pledge_stdio
    pid = Process.fork do
      jail.attach
      if pid.nil?
        ##
        # child
        pledge("inet", nil)
        assert_raise(Errno::ENOTCAPABLE) do
          File.open("/stdio.txt") { f.write("fail") }
          exit(42)
        end
      else
        ##
        # parent
        Process.wait(pid)
        assert_equal 42, $?.exitstatus
      end
    end
  end

  private

  ##
  # Isolate our tests in a separate jail.
  # @return [Jail]
  def jail
    @jail ||= Jail.create(
      settings.merge(persist: true)
    )
  end

  ##
  # @return [Hash]
  def settings
    {name: "tmpjail", path: File.join("tmp", "jail")}
  end
end
