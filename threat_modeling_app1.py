import streamlit as st
import base64
import re
from graphviz import Digraph, ExecutableNotFound
from PIL import Image, ImageDraw, ImageFont
import io

# Streamlit app configuration
st.set_page_config(page_title="Threat Modeling Through Cars", page_icon="🚗", layout="wide")

# Current date and time (05:58 PM AEST, Saturday, July 19, 2025)
current_datetime = "05:58 PM AEST, Saturday, July 19, 2025"

# HTML content as a string
html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Modeling: Cars Security Story</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(45deg, #2c3e50, #3498db);
            color: white;
            text-align: center;
            padding: 30px 20px;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
        }
        
        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .story-nav {
            display: flex;
            justify-content: center;
            gap: 20px;
            padding: 20px;
            background: #f8f9fa;
            border-bottom: 2px solid #e9ecef;
        }
        
        .nav-btn {
            padding: 12px 24px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            border: none;
            border-radius: 25px;
            cursor: pointer;
            font-size: 1.1em;
            font-weight: 600;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }
        
        .nav-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
        }
        
        .nav-btn.active {
            background: linear-gradient(45deg, #e74c3c, #c0392b);
            box-shadow: 0 4px 15px rgba(231, 76, 60, 0.3);
        }
        
        .story-content {
            padding: 40px;
            min-height: 600px;
            display: none;
        }
        
        .story-content.active {
            display: block;
            animation: fadeIn 0.5s ease-in;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .car-comparison {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-top: 30px;
        }
        
        .car-section {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
            border: 3px solid transparent;
            transition: all 0.3s ease;
        }
        
        .car-section:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.15);
        }
        
        .normal-car {
            border-color: #27ae60;
        }
        
        .f1-car {
            border-color: #e74c3c;
        }
        
        .car-title {
            font-size: 1.8em;
            font-weight: bold;
            margin-bottom: 15px;
            text-align: center;
            padding: 10px;
            border-radius: 10px;
            color: white;
        }
        
        .normal-car .car-title {
            background: linear-gradient(45deg, #27ae60, #2ecc71);
        }
        
        .f1-car .car-title {
            background: linear-gradient(45deg, #e74c3c, #c0392b);
        }
        
        .car-visual {
            text-align: center;
            font-size: 4em;
            margin: 20px 0;
            animation: bounce 2s infinite;
        }
        
        @keyframes bounce {
            0%, 20%, 50%, 80%, 100% { transform: translateY(0); }
            40% { transform: translateY(-10px); }
            60% { transform: translateY(-5px); }
        }
        
        .threats-list, .controls-list {
            margin: 20px 0;
        }
        
        .threats-list h3, .controls-list h3 {
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 1.3em;
            border-bottom: 2px solid #3498db;
            padding-bottom: 5px;
        }
        
        .threat-item, .control-item {
            background: #f8f9fa;
            margin: 10px 0;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid;
            transition: all 0.3s ease;
        }
        
        .threat-item {
            border-left-color: #e74c3c;
        }
        
        .control-item {
            border-left-color: #27ae60;
        }
        
        .threat-item:hover, .control-item:hover {
            transform: translateX(5px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }
        
        .relevance-indicator {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: bold;
            margin-left: 10px;
        }
        
        .high-relevance {
            background: #e74c3c;
            color: white;
        }
        
        .medium-relevance {
            background: #f39c12;
            color: white;
        }
        
        .low-relevance {
            background: #95a5a6;
            color: white;
        }
        
        .lesson-box {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            padding: 25px;
            border-radius: 15px;
            margin: 30px 0;
            text-align: center;
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }
        
        .lesson-box h3 {
            font-size: 1.5em;
            margin-bottom: 15px;
        }
        
        .interactive-element {
            background: white;
            border: 2px dashed #3498db;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .interactive-element:hover {
            background: #ecf0f1;
            border-color: #2980b9;
            transform: scale(1.02);
        }
        
        .scenario-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        
        .scenario-card {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
            border-top: 4px solid #3498db;
            transition: all 0.3s ease;
        }
        
        .scenario-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 30px rgba(0, 0, 0, 0.15);
        }
        
        @media (max-width: 768px) {
            .car-comparison {
                grid-template-columns: 1fr;
            }
            
            .story-nav {
                flex-direction: column;
                gap: 10px;
            }
            
            .nav-btn {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚗 Threat Modeling Through Cars 🏎️</h1>
            <p>Understanding how different environments require different security controls. Generated on: """ + current_datetime + """</p>
        </div>
        
        <div class="story-nav">
            <button class="nav-btn active" onclick="showStory('intro')">Introduction</button>
            <button class="nav-btn" onclick="showStory('fundamentals')">TM Fundamentals</button>
            <button class="nav-btn" onclick="showStory('threats')">Threat Analysis</button>
            <button class="nav-btn" onclick="showStory('controls')">Security Controls</button>
            <button class="nav-btn" onclick="showStory('lessons')">Key Lessons</button>
        </div>
        
        <div id="intro" class="story-content active">
            <h2 style="text-align: center; color: #2c3e50; margin-bottom: 30px;">The Tale of Two Cars</h2>
            
            <div class="car-comparison">
                <div class="car-section normal-car">
                    <div class="car-title">Sarah's Family Car</div>
                    <div class="car-visual">🚗</div>
                    <p><strong>Environment:</strong> City streets, highways, parking lots, home garage</p>
                    <p><strong>Primary Users:</strong> Family members of varying experience levels</p>
                    <p><strong>Usage Pattern:</strong> Daily commuting, errands, road trips</p>
                    <p><strong>Asset Value:</strong> Transportation, family safety, personal property</p>
                </div>
                
                <div class="car-section f1-car">
                    <div class="car-title">Max's Formula 1 Car</div>
                    <div class="car-visual">🏎️</div>
                    <p><strong>Environment:</strong> Controlled race tracks, pit lanes, secured facilities</p>
                    <p><strong>Primary Users:</strong> Professional driver, trained pit crew</p>
                    <p><strong>Usage Pattern:</strong> High-speed racing, performance optimization</p>
                    <p><strong>Asset Value:</strong> Racing performance, competitive advantage, team reputation</p>
                </div>
            </div>
            
            <div class="lesson-box">
                <h3>🎯 Threat Modeling Principle #1</h3>
                <p>The same type of asset (a car) requires completely different security controls based on its environment, users, and purpose. Context is everything in threat modeling!</p>
            </div>
            
            <div class="interactive-element" onclick="showStory('threats')">
                <h3>🔍 Click to Analyze the Threats Each Car Faces</h3>
                <p>Let's dive deeper into what each car needs to protect against...</p>
            </div>
        </div>
        
        <div id="fundamentals" class="story-content">
            <h2 style="text-align: center; color: #2c3e50; margin-bottom: 30px;">🔍 Threat Modeling Fundamentals</h2>
            
            <div class="lesson-box">
                <h3>What is Threat Modeling?</h3>
                <p>Threat modeling is a structured approach to identifying security risks and determining appropriate countermeasures. Think of it as creating a "security blueprint" for your system - just like our cars need different safety features for different environments.</p>
            </div>
            
            <!-- Enhanced Threat Model Diagram -->
            <div style="background: white; border-radius: 15px; padding: 30px; margin: 30px 0; box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);">
                <h3 style="text-align: center; color: #2c3e50; margin-bottom: 25px;">🗺️ Threat Model Flow</h3>
                <svg viewBox="0 0 1000 700" style="width: 100%; height: auto; max-height: 500px;">
                    <!-- System -->
                    <rect x="50" y="150" width="120" height="80" rx="10" fill="#3498db" stroke="#2980b9" stroke-width="3"/>
                    <text x="110" y="195" text-anchor="middle" fill="white" font-size="16" font-weight="bold">System</text>
                    <text x="110" y="210" text-anchor="middle" fill="white" font-size="12">(Car)</text>
                    
                    <!-- Data Stores -->
                    <rect x="50" y="50" width="120" height="60" rx="10" fill="#27ae60" stroke="#229954" stroke-width="3"/>
                    <text x="110" y="85" text-anchor="middle" fill="white" font-size="16" font-weight="bold">Data</text>
                    <text x="110" y="100" text-anchor="middle" fill="white" font-size="12">(Telemetry)</text>
                    
                    <!-- Functionality -->
                    <rect x="50" y="280" width="120" height="80" rx="10" fill="#8e44ad" stroke="#7d3c98" stroke-width="3"/>
                    <text x="110" y="320" text-anchor="middle" fill="white" font-size="14" font-weight="bold">Functionality</text>
                    <text x="110" y="335" text-anchor="middle" fill="white" font-size="12">(Driving)</text>
                    
                    <!-- Value -->
                    <rect x="270" y="100" width="120" height="80" rx="10" fill="#f39c12" stroke="#e67e22" stroke-width="3"/>
                    <text x="330" y="145" text-anchor="middle" fill="white" font-size="16" font-weight="bold">Value</text>
                    <text x="330" y="160" text-anchor="middle" fill="white" font-size="12">(What's Protected)</text>
                    
                    <!-- Risk -->
                    <rect x="490" y="100" width="120" height="80" rx="10" fill="#e74c3c" stroke="#c0392b" stroke-width="3"/>
                    <text x="550" y="145" text-anchor="middle" fill="white" font-size="16" font-weight="bold">Risk</text>
                    <text x="550" y="160" text-anchor="middle" fill="white" font-size="12">(Impact)</text>
                    
                    <!-- Threat -->
                    <rect x="490" y="280" width="120" height="80" rx="10" fill="#e67e22" stroke="#d35400" stroke-width="3"/>
                    <text x="550" y="320" text-anchor="middle" fill="white" font-size="16" font-weight="bold">Threat</text>
                    <text x="550" y="335" text-anchor="middle" fill="white" font-size="12">(Danger)</text>
                    
                    <!-- Vulnerability -->
                    <rect x="700" y="280" width="120" height="80" rx="10" fill="#95a5a6" stroke="#7f8c8d" stroke-width="3"/>
                    <text x="760" y="315" text-anchor="middle" fill="white" font-size="14" font-weight="bold">Vulnerability</text>
                    <text x="760" y="330" text-anchor="middle" fill="white" font-size="12">(Weakness)</text>
                    <text x="760" y="345" text-anchor="middle" fill="white" font-size="12">(Exploitable)</text>
                    
                    <!-- Weakness -->
                    <rect x="490" y="450" width="120" height="80" rx="10" fill="#34495e" stroke="#2c3e50" stroke-width="3"/>
                    <text x="550" y="490" text-anchor="middle" fill="white" font-size="16" font-weight="bold">Weakness</text>
                    <text x="550" y="505" text-anchor="middle" fill="white" font-size="12">(Flaw)</text>
                    
                    <!-- Actor -->
                    <ellipse cx="750" cy="150" rx="60" ry="40" fill="#16a085" stroke="#138d75" stroke-width="3"/>
                    <text x="750" y="155" text-anchor="middle" fill="white" font-size="16" font-weight="bold">Actor</text>
                    <text x="750" y="170" text-anchor="middle" fill="white" font-size="12">(Attacker)</text>
                    
                    <!-- Trust Boundary -->
                    <rect x="30" y="30" width="600" height="520" rx="20" fill="none" stroke="#e74c3c" stroke-width="4" stroke-dasharray="10,5" opacity="0.7"/>
                    <text x="330" y="25" text-anchor="middle" fill="#e74c3c" font-size="14" font-weight="bold">Trust Boundary</text>
                    
                    <!-- Data Flow Arrows -->
                    <defs>
                        <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
                            <polygon points="0 0, 10 3.5, 0 7" fill="#2c3e50"/>
                        </marker>
                    </defs>
                    
                    <!-- System → Data -->
                    <line x1="110" y1="150" x2="110" y2="120" stroke="#2c3e50" stroke-width="3" marker-end="url(#arrowhead)"/>
                    <text x="90" y="135" fill="#2c3e50" font-size="12" font-weight="bold">Has</text>
                    
                    <!-- Data → Value -->
                    <line x1="170" y1="80" x2="270" y2="130" stroke="#2c3e50" stroke-width="3" marker-end="url(#arrowhead)"/>
                    <text x="200" y="100" fill="#2c3e50" font-size="12" font-weight="bold">Creates</text>
                    
                    <!-- Value → Risk -->
                    <line x1="390" y1="140" x2="490" y2="140" stroke="#2c3e50" stroke-width="3" marker-end="url(#arrowhead)"/>
                    <text x="420" y="135" fill="#2c3e50" font-size="12" font-weight="bold">Informs</text>
                    
                    <!-- System → Functionality -->
                    <line x1="110" y1="230" x2="110" y2="280" stroke="#2c3e50" stroke-width="3" marker-end="url(#arrowhead)"/>
                    <text x="75" y="255" fill="#2c3e50" font-size="12" font-weight="bold">Creates</text>
                    
                    <!-- System → Value -->
                    <line x1="170" y1="175" x2="270" y2="155" stroke="#2c3e50" stroke-width="3" marker-end="url(#arrowhead)"/>
                    <text x="200" y="165" fill="#2c3e50" font-size="12" font-weight="bold">Exposes</text>
                    
                    <!-- Functionality → Weakness -->
                    <line x1="170" y1="340" x2="490" y2="470" stroke="#2c3e50" stroke-width="3" marker-end="url(#arrowhead)"/>
                    <text x="300" y="400" fill="#2c3e50" font-size="12" font-weight="bold">Contains</text>
                    
                    <!-- Weakness → Vulnerability -->
                    <line x1="610" y1="490" x2="700" y2="350" stroke="#2c3e50" stroke-width="3" marker-end="url(#arrowhead)"/>
                    <text x="650" y="430" fill="#2c3e50" font-size="12" font-weight="bold">Results in</text>
                    
                    <!-- Threat → Vulnerability -->
                    <line x1="610" y1="320" x2="700" y2="320" stroke="#2c3e50" stroke-width="3" marker-end="url(#arrowhead)"/>
                    <text x="635" y="315" fill="#2c3e50" font-size="12" font-weight="bold">Exploits</text>
                    
                    <!-- Risk → Threat -->
                    <line x1="550" y1="180" x2="550" y2="280" stroke="#2c3e50" stroke-width="3" marker-end="url(#arrowhead)"/>
                    <text x="560" y="230" fill="#2c3e50" font-size="12" font-weight="bold">Generates</text>
                    
                    <!-- Actor → Threat -->
                    <line x1="690" y1="160" x2="610" y2="300" stroke="#2c3e50" stroke-width="3" marker-end="url(#arrowhead)"/>
                    <text x="630" y="220" fill="#2c3e50" font-size="12" font-weight="bold">Causes</text>
                    
                    <!-- Functionality breaks weakness arrow -->
                    <line x1="170" y1="320" x2="490" y2="490" stroke="#e74c3c" stroke-width="3" marker-end="url(#arrowhead)" stroke-dasharray="5,5"/>
                    <text x="300" y="420" fill="#e74c3c" font-size="12" font-weight="bold">Breaks</text>
                </svg>
            </div>
            
            <!-- Data Flow Concepts -->
            <div class="car-comparison">
                <div class="car-section normal-car">
                    <div class="car-title">🔄 Data Flows in Sarah's Car</div>
                    <div class="threats-list">
                        <h3>📊 Key Data Flows:</h3>
                        <div class="threat-item">
                            <strong>GPS → Navigation System</strong>
                            <br>Location data flows to provide directions
                        </div>
                        <div class="threat-item">
                            <strong>Engine → Dashboard</strong>
                            <br>Performance metrics displayed to driver
                        </div>
                        <div class="threat-item">
                            <strong>Phone → Car Audio</strong>
                            <br>Bluetooth connection for calls/music
                        </div>
                        <div class="threat-item">
                            <strong>Key Fob → Door Locks</strong>
                            <br>Authentication signal to unlock vehicle
                        </div>
                    </div>
                </div>
                
                <div class="car-section f1-car">
                    <div class="car-title">🔄 Data Flows in Max's F1 Car</div>
                    <div class="threats-list">
                        <h3>📊 Key Data Flows:</h3>
                        <div class="threat-item">
                            <strong>Sensors → Telemetry System</strong>
                            <br>Real-time performance data to pit crew
                        </div>
                        <div class="threat-item">
                            <strong>Strategy → Driver Radio</strong>
                            <br>Encrypted communications from pit wall
                        </div>
                        <div class="threat-item">
                            <strong>Car Setup → ECU</strong>
                            <br>Configuration data controlling car behavior
                        </div>
                        <div class="threat-item">
                            <strong>Biometrics → Garage Access</strong>
                            <br>Identity verification for restricted areas
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Trust Boundaries -->
            <div style="background: linear-gradient(135deg, #ff6b6b, #feca57); color: white; padding: 25px; border-radius: 15px; margin: 30px 0;">
                <h3 style="margin-bottom: 20px;">🔒 Trust Boundaries - The Security Perimeter</h3>
                <div class="car-comparison" style="gap: 20px;">
                    <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 10px;">
                        <h4>Sarah's Trust Boundaries:</h4>
                        <ul style="margin-left: 20px; line-height: 1.6;">
                            <li><strong>Physical:</strong> Locked doors and windows</li>
                            <li><strong>Digital:</strong> Encrypted key fob communication</li>
                            <li><strong>Network:</strong> Bluetooth pairing authentication</li>
                            <li><strong>User:</strong> Family members vs strangers</li>
                        </ul>
                    </div>
                    <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 10px;">
                        <h4>Max's Trust Boundaries:</h4>
                        <ul style="margin-left: 20px; line-height: 1.6;">
                            <li><strong>Physical:</strong> Secured garage with guards</li>
                            <li><strong>Digital:</strong> Encrypted telemetry channels</li>
                            <li><strong>Network:</strong> Private team communications</li>
                            <li><strong>Personnel:</strong> Team members vs competitors</li>
                        </ul>
                    </div>
                </div>
            </div>
            
            <div class="interactive-element" onclick="showStory('threats')">
                <h3>🎯 Ready to Analyze Threats?</h3>
                <p>Now that you understand the fundamentals, let's see how they apply to our car examples...</p>
            </div>
        </div>
        
        <div id="threats" class="story-content">
            <h2 style="text-align: center; color: #2c3e50; margin-bottom: 30px;">Threat Landscape Analysis</h2>
            
            <div class="car-comparison">
                <div class="car-section normal-car">
                    <div class="car-title">Sarah's Family Car Threats</div>
                    <div class="car-visual">🚗⚠️</div>
                    <div class="threats-list">
                        <h3>🎯 Primary Threats:</h3>
                        <div class="threat-item">
                            <strong>Theft/Break-ins</strong> <span class="relevance-indicator high-relevance">HIGH</span>
                            <br>Car left unattended in public spaces, valuable items visible
                        </div>
                        <div class="threat-item">
                            <strong>Accidents</strong> <span class="relevance-indicator high-relevance">HIGH</span>
                            <br>Other drivers, weather conditions, mechanical failures
                        </div>
                        <div class="threat-item">
                            <strong>Unauthorized Use</strong> <span class="relevance-indicator medium-relevance">MEDIUM</span>
                            <br>Family members, friends, valet parking situations
                        </div>
                        <div class="threat-item">
                            <strong>Vandalism</strong> <span class="relevance-indicator medium-relevance">MEDIUM</span>
                            <br>Property damage in uncontrolled environments
                        </div>
                        <div class="threat-item">
                            <strong>Child Safety Risks</strong> <span class="relevance-indicator high-relevance">HIGH</span>
                            <br>Children accidentally opening doors, unbuckling restraints
                        </div>
                        <div class="threat-item">
                            <strong>Distracted Driving</strong> <span class="relevance-indicator high-relevance">HIGH</span>
                            <br>Mobile phones, passengers, navigation systems
                        </div>
                        <div class="threat-item">
                            <strong>Tire Failure</strong> <span class="relevance-indicator medium-relevance">MEDIUM</span>
                            <br>Blowouts on highways due to poor maintenance
                        </div>
                    </div>
                </div>
                
                <div class="car-section f1-car">
                    <div class="car-title">Max's F1 Car Threats</div>
                    <div class="car-visual">🏎️⚠️</div>
                    <div class="threats-list">
                        <h3>🎯 Primary Threats:</h3>
                        <div class="threat-item">
                            <strong>Performance Sabotage</strong> <span class="relevance-indicator high-relevance">HIGH</span>
                            <br>Competitors tampering with car setup or components
                        </div>
                        <div class="threat-item">
                            <strong>Data Espionage</strong> <span class="relevance-indicator high-relevance">HIGH</span>
                            <br>Telemetry data, setup secrets, technical innovations
                        </div>
                        <div class="threat-item">
                            <strong>Catastrophic Failure</strong> <span class="relevance-indicator high-relevance">HIGH</span>
                            <br>Life-threatening mechanical failures at 200+ mph
                        </div>
                        <div class="threat-item">
                            <strong>Unauthorized Access</strong> <span class="relevance-indicator medium-relevance">MEDIUM</span>
                            <br>Media, fans, or competitors accessing restricted areas
                        </div>
                        <div class="threat-item">
                            <strong>Fire Hazards</strong> <span class="relevance-indicator high-relevance">HIGH</span>
                            <br>High-octane fuel, hot exhausts, electrical systems at extreme stress
                        </div>
                        <div class="threat-item">
                            <strong>Equipment Tampering</strong> <span class="relevance-indicator high-relevance">HIGH</span>
                            <br>Competitors loosening wheel nuts, contaminating fuel
                        </div>
                        <div class="threat-item">
                            <strong>Communication Interception</strong> <span class="relevance-indicator medium-relevance">MEDIUM</span>
                            <br>Radio communications with strategy information
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="lesson-box">
                <h3>📊 Threat Modeling Principle #2</h3>
                <p>Different assets face completely different threat landscapes. A family car worries about theft and everyday accidents, while an F1 car focuses on competitive intelligence and performance integrity.</p>
            </div>
        </div>
        
        <div id="controls" class="story-content">
            <h2 style="text-align: center; color: #2c3e50; margin-bottom: 30px;">Security Controls Comparison</h2>
            
            <div class="car-comparison">
                <div class="car-section normal-car">
                    <div class="car-title">Sarah's Family Car Controls</div>
                    <div class="car-visual">🚗🔒</div>
                    <div class="controls-list">
                        <h3>🛡️ Key Security Controls:</h3>
                        <div class="control-item">
                            <strong>Door Locks & Alarm System</strong> <span class="relevance-indicator high-relevance">CRITICAL</span>
                            <br>Essential for preventing theft and unauthorized access
                        </div>
                        <div class="control-item">
                            <strong>Airbags & Seat Belts</strong> <span class="relevance-indicator high-relevance">CRITICAL</span>
                            <br>Protect occupants during accidents
                        </div>
                        <div class="control-item">
                            <strong>Anti-lock Brakes (ABS)</strong> <span class="relevance-indicator high-relevance">CRITICAL</span>
                            <br>Prevent skidding in emergency situations
                        </div>
                        <div class="control-item">
                            <strong>Backup Camera & Sensors</strong> <span class="relevance-indicator medium-relevance">IMPORTANT</span>
                            <br>Help prevent low-speed collisions
                        </div>
                        <div class="control-item">
                            <strong>Child Safety Locks</strong> <span class="relevance-indicator high-relevance">CRITICAL</span>
                            <br>Prevent children from opening doors while driving
                        </div>
                        <div class="control-item">
                            <strong>Tire Pressure Monitoring</strong> <span class="relevance-indicator medium-relevance">IMPORTANT</span>
                            <br>Prevents dangerous blowouts at highway speeds
                        </div>
                        <div class="control-item">
                            <strong>Roll Cage</strong> <span class="relevance-indicator low-relevance">UNNECESSARY</span>
                            <br>Would block visibility and accessibility for daily use
                        </div>
                        <div class="control-item">
                            <strong>Racing Harness</strong> <span class="relevance-indicator low-relevance">IMPRACTICAL</span>
                            <br>Too complex for multiple daily entries/exits
                        </div>
                    </div>
                </div>
                
                <div class="car-section f1-car">
                    <div class="car-title">Max's F1 Car Controls</div>
                    <div class="car-visual">🏎️🔒</div>
                    <div class="controls-list">
                        <h3>🛡️ Key Security Controls:</h3>
                        <div class="control-item">
                            <strong>Real-time Telemetry Encryption</strong> <span class="relevance-indicator high-relevance">CRITICAL</span>
                            <br>Protect performance data from competitors
                        </div>
                        <div class="control-item">
                            <strong>Physical Access Controls</strong> <span class="relevance-indicator high-relevance">CRITICAL</span>
                            <br>Restricted garage access, security personnel
                        </div>
                        <div class="control-item">
                            <strong>Component Authentication</strong> <span class="relevance-indicator high-relevance">CRITICAL</span>
                            <br>Ensure all parts are genuine and unmodified
                        </div>
                        <div class="control-item">
                            <strong>Advanced Safety Systems</strong> <span class="relevance-indicator high-relevance">CRITICAL</span>
                            <br>HALO device, fire suppression, emergency communications
                        </div>
                        <div class="control-item">
                            <strong>Driver Helmet & HANS Device</strong> <span class="relevance-indicator high-relevance">CRITICAL</span>
                            <br>Essential protection at 200+ mph; would impair normal driving
                        </div>
                        <div class="control-item">
                            <strong>Roll Cage & Racing Harness</strong> <span class="relevance-indicator high-relevance">CRITICAL</span>
                            <br>Structural protection for high-speed impacts
                        </div>
                        <div class="control-item">
                            <strong>Fire Suppression System</strong> <span class="relevance-indicator high-relevance">CRITICAL</span>
                            <br>Automatic fire extinguisher due to fuel and heat risks
                        </div>
                        <div class="control-item">
                            <strong>Traditional Car Alarms</strong> <span class="relevance-indicator low-relevance">IRRELEVANT</span>
                            <br>Unnecessary in controlled race environment
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="lesson-box">
                <h3>⚖️ Threat Modeling Principle #3</h3>
                <p>Security controls must be tailored to the specific threats. What's critical for one environment may be irrelevant or even counterproductive in another. F1 cars need encryption and access controls, while family cars need theft deterrence and collision protection.</p>
            </div>
        </div>
        
        <div id="lessons" class="story-content">
            <h2 style="text-align: center; color: #2c3e50; margin-bottom: 30px;">Key Threat Modeling Lessons</h2>
            
            <div class="scenario-grid">
                <div class="scenario-card">
                    <h3>🎯 Context Matters</h3>
                    <p>The same asset (car) requires different security controls based on its environment, users, and purpose. Always start by understanding your specific context.</p>
                </div>
                
                <div class="scenario-card">
                    <h3>📊 Threat Prioritization</h3>
                    <p>Not all threats are equal. Sarah worries about theft; Max worries about espionage. Focus your security efforts on the threats most relevant to your situation.</p>
                </div>
                
                <div class="scenario-card">
                    <h3>🛡️ Control Effectiveness</h3>
                    <p>A car alarm is vital for Sarah but useless for Max. Security controls must match the actual threats you face, not generic "best practices."</p>
                </div>
                
                <div class="scenario-card">
                    <h3>⚡ Performance vs Security</h3>
                    <p>F1 cars prioritize performance over convenience (no power steering, minimal comfort). Sometimes security requirements force trade-offs with other goals.</p>
                </div>
                
                <div class="scenario-card">
                    <h3>🪖 Safety Equipment</h3>
                    <p>Helmets are mandatory for F1 drivers but would impair vision and comfort for family drivers. Racing harnesses provide superior crash protection but are too complex for daily use.</p>
                </div>
                
                <div class="scenario-card">
                    <h3>🔐 Access Controls</h3>
                    <p>F1 cars need biometric garage access and component authentication. Family cars need simple key fobs and basic alarms that family members can easily use.</p>
                </div>
                
                <div class="scenario-card">
                    <h3>🔥 Emergency Systems</h3>
                    <p>F1 cars have automatic fire suppression and quick-release steering wheels. Family cars rely on airbags and crumple zones - fire systems would add cost and complexity without benefit.</p>
                </div>
                
                <div class="scenario-card">
                    <h3>👶 Child Safety</h3>
                    <p>Family cars need child locks, car seat anchors, and rear door safety features. F1 cars are single-occupant vehicles where such features would be pointless weight.</p>
                </div>
            </div>
            
            <div class="lesson-box">
                <h3>🎓 The Threat Modeling Process</h3>
                <p><strong>1.</strong> Identify your assets and their value<br>
                <strong>2.</strong> Understand your operating environment<br>
                <strong>3.</strong> Catalog relevant threats for YOUR context<br>
                <strong>4.</strong> Prioritize threats by likelihood and impact<br>
                <strong>5.</strong> Select controls that address your priority threats<br>
                <strong>6.</strong> Regularly reassess as context changes</p>
            </div>
            
            <div class="interactive-element">
                <h3>🚀 Ready to Apply This to Your Organization?</h3>
                <p>Think about your own systems: What are your "family car" assets that need basic, user-friendly protection? What are your "F1 car" assets that require specialized, high-performance security controls?</p>
                <br>
                <p><em>Remember: The goal isn't to have the most security controls—it's to have the RIGHT security controls for YOUR specific threats.</em></p>
            </div>
        </div>
    </div>
    
    <script>
        function showStory(section) {
            // Hide all content sections
            const contents = document.querySelectorAll('.story-content');
            contents.forEach(content => {
                content.classList.remove('active');
            });
            
            // Remove active class from all buttons
            const buttons = document.querySelectorAll('.nav-btn');
            buttons.forEach(button => {
                button.classList.remove('active');
            });
            
            // Show selected section
            document.getElementById(section).classList.add('active');
            
            // Add active class to clicked button
            event.target.classList.add('active');
        }
        
        // Add some interactive behavior
        document.addEventListener('DOMContentLoaded', function() {
            const interactiveElements = document.querySelectorAll('.interactive-element');
            interactiveElements.forEach(element => {
                element.addEventListener('click', function() {
                    this.style.background = '#e8f5e8';
                    setTimeout(() => {
                        this.style.background = 'white';
                    }, 200);
                });
            });
        });
    </script>
</body>
</html>
"""

# Display the HTML content using Streamlit
st.components.v1.html(html_content, height=1000, scrolling=True)

# Footer
st.markdown("""
---
*Built with Streamlit | Learn more at [OWASP](https://owasp.org/www-community/Threat_Modeling).*
""")
