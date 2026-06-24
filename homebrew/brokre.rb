class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.2.10"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.10/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "4e05ce8c587319ad05ede0af5802de6c18a13c185dee56f1c6a5aa02ca98e75e"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.10/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "a2428fadf5bada2beb332ad5282b42ecfc7ba3a2f879aa8637b08c72a158339e"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.10/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "295814491ca7c8d251acdf6765e7d9df664204f1038612d9b1ff0e9fedd92e86"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.2.10/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "ac4bab273a7e517bd1dde88aa68a6c41977108cc64309d3ef8d6a1e863a4db79"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end
