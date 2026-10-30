class RPathTest < Picotest::Test
  def setup
    jail
  end

  def teardown
    jail.remove
  end

  def test_pledge_rpath_denied
    pid = Process.fork do
      jail.attach
      ##
      # child
      puts "in child"
      pledge("proc stdio", nil)
      File.open("/stdio.txt", "r") { }
      exit(1)
    end
    ##
    # parent
    puts "in parent"
    Process.wait(pid)
    assert_equal nil, $?.exitstatus
  end

  def test_pledge_rpath_allowed
    pid = Process.fork do
     jail.attach
      ##
      # child
      puts "in child"
      pledge("proc stdio rpath", nil)
      File.open("/stdio.txt", "r") { }
      exit(1)
    end
    ##
    # parent
    puts "in parent"
    Process.wait(pid)
    assert_equal 1, $?.exitstatus
  end

  private

  ##
  # Isolate our tests in a separate jail.
  # @return [Jail]
  def jail
    @jail ||= Jail.create(**settings)
  end

  ##
  # @return [Hash]
  def settings
    {name: "tmpjail",
     hostname: "test.hardenedbsd.org",
     path: File.join("/tmp", "jail"),
     persist: 1,
    "security.pledge.enforcing" => 1}
  end
end
