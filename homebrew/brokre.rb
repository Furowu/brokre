class Brokre < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokre"
  version "0.1.32"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.32/brokre-x86_64-apple-darwin.tar.gz"
    sha256 "41a146771460593d4ebf1b9dde0f716aa05d3e79999f0a65b6b3278a42856d68"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.32/brokre-aarch64-apple-darwin.tar.gz"
    sha256 "ae2eb1f094fb749d19605bbf666ee52a6a2d6caabd34a2bf9dacdccf2908ec04"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.32/brokre-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "d59e2a3c0d6c4d344b6c77d6167259b6505867cce4dd280313054d052520ec31"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/Furowu/brokre/releases/download/v0.1.32/brokre-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "6c3722de86ef6990518ba113432209f9aae97a0797065e3a706f86b66d237a82"
  end

  def install
    bin.install "brokre"
  end

  test do
    system "#{bin}/brokre", "--version"
  end
end
