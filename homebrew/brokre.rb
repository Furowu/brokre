class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.19"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.19/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "18c108fa9b35a924d29331f06833eb5965500b61c1b9f46c004458451a732ca0"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.19/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "eb3e63e8b2ab293592f453a3d52a10a1b1488cfe9f22b9b8fc1ae4247fb2abba"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.19/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "da209f7316ea1ca139f2474ece25d6241396a5621904b5e5232596ac85f1c7b0"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.19/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "1b564bae449c15b54204d650991a21bb29f4a9fbffc7eb255ce66c7e182a03b0"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end
