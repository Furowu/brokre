class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.27"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.27/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "03d8f9fc0dcf0c6e4ccab02fb08e0e00a4b50a26195f82b2ff3fd33d635810d2"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.27/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "dd71b1cd2da1e3941da4cf73e027c75cab92c04a418fb78017fc15873321db44"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.27/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "b2b144a37a723d847cfa0651967e747a561ccdf0cccd68f3c995105ca6dc22db"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.27/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "9ef7875b0c83f652856acb82e2b770eb87c612b3cc113000f032c6ac5e2ffb85"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end
