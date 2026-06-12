class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.1.8"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.8/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "4f482cba8dcdf39a04e529041d0d914ebdd205370dab4b79ff020572f546e9a4"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.8/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "3dd74867c431343cd86e443cd7571d29a38f0a059e8514f224ab497ef4123f28"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.8/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "9e6fea2f48979ff50e488b76c497fe181d13fd976a8128f092dba0074d0f5eb2"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.8/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "aba01ad2a8c9756bcedd0f034ff69083cae03f4de8e70abbc0d0f809634db3fb"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end
