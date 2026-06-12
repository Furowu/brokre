class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.1.21"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.21/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "221adecfe30fbd27b7758d143be43c72d95f9ed9d9d8294f7300a45c7120ae01"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.21/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "1c6000ac5f92f8b729976708b75b5cd84756eab169bd5867ea695ed9f35ed4dd"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.21/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "a33f47042a2ec92e842b8ef43a6bf53bf5bbd7d7051b3d2d121dc1e82bb6b39e"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.21/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "46bb3821113821f0b0a5746b2ba0ac9ae6ad8c034f36c55837a3774fd34d7170"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end
