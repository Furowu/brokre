class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.25"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.25/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "4dc00c2fe905c825d2017ea6b1abb1e9143a0839ba3204614d1227b219321ce0"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.25/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "fe78034a9e1bcef6af67248a24a68956275d78626e6663d605f0d6da891ebff2"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.25/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "639d5442ebb217017359716afc6add394887e4eb99ecebb89b2984f6e9a69a36"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.25/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "e4ef5517e7c85afece28afad3490a67a3b890eaba58dbecd77251550fd918418"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end
