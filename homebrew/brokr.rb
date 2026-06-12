class Brokr < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokr"
  version "0.1.4"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokr/releases/download/v0.1.4/brokr-x86_64-apple-darwin.tar.gz"
    sha256 "78ff2c7c9f46c87592cb55ce7c4d3d111f9ca6fd79cfee31bc4fb8559c8b2b4a"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokr/releases/download/v0.1.4/brokr-aarch64-apple-darwin.tar.gz"
    sha256 "010fc8d9f91ed6e026e7829d7d384dc4c7d206caa729a6671b129eb6b9e532f4"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokr/releases/download/v0.1.4/brokr-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "c7d43b7f6116890cd61dd5426d54e5cb055aecb7e6ca2933308b2127dfc01671"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokr/releases/download/v0.1.4/brokr-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "5ce194c53231d57435741b5bfb9e67b6526faddd61deec159e4f93a6ea0abc6f"
  end

  def install
    bin.install "brokr"
  end

  test do
    system "#{bin}/brokr", "--version"
  end
end
