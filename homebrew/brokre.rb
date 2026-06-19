class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.1.31"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.31/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "85fe693dba3b0c80d74e70f17f54ac38f2933ebe1c659290576995aa69b886f2"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.31/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "59b6f631040b33197e038667a2705791496de10823768fa39b852204ca2deb37"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.31/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "978edf86a3593c248a2b39f54c83b462d8d571689a30856654474f469832d249"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.31/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "93e672010d89007448f772279bae7e96eba3b1e66496867cece07af8ab6e35a9"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end
