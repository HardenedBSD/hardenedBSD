class PledgeTest < Picotest::Test
  def setup
    jail
  end

  def teardown
    jail.remove
  end

  def test_pledge_rpath
    pid = Process.fork do
     jail.attach
      ##
      # child
      puts "in child"
      pledge("", nil)
      assert_raise(Errno::ENOTCAPABLE) do
        File.open("/stdio.txt") { f.write("fail") }
      end
      exit(1)
    end
    ##
    # parent
    puts "in parent"
    Process.wait(pid)
    assert_equal nil, $?.exitstatus
  end

  private

  ##
  # Isolate our tests in a separate jail.
  # @return [Jail]
  def jail
    @jail ||= Jail.create(
      **settings.merge(persist: 1)
    )
  end

  ##
  # @return [Hash]
  def settings
    {name: "tmpjail",
     hostname: "test.hardenedbsd.org",
     path: File.join("/tmp", "jail"),
    "security.pledge.enforcing" => 1}
  end
end
